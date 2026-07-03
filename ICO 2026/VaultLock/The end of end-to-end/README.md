---
title: "The end of end-to-end"
ctf: "ICO 2026"
task: "VaultLock"
date: 2026-06-30
category: crypto
difficulty: medium
points: 35
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# The end of end-to-end (VaultLock e2e cipher break)

## Summary

`gui/client.py` implements a "custom cipher" so that saved passwords are
end-to-end encrypted before ever reaching the app/DB — the server only
ever sees ciphertext. Two independent design flaws combine to defeat
this entirely, with no need to touch the app's JWT/DSA auth at all:

1. The `db` service (port 8080, published by `docker-compose.yml`) answers
   `get_passwords` with only a `username` — no session, token, or
   signature check at that layer — so any client on the network can dump
   any account's stored (encrypted) password blobs directly.
2. The cipher itself is a 3-round Feistel network built from modular
   **addition** (not XOR) around a public-form, bounded-degree polynomial
   round function. That structure is linear enough in its unknown
   coefficients that ordinary known-plaintext pairs solve for the whole
   round function algebraically — no key needed.

`dispatcher_flag4.py` conveniently seeds `flag4_user`'s vault with 11
passwords whose plaintexts are hardcoded in the dispatcher itself, all
encrypted under the same session key. That's exactly the known-plaintext
material needed to break the cipher and decrypt the `flag4` entry sitting
right next to them.

## Solution

### Step 1: Read the ciphertexts straight from the DB, no auth needed

`db.py`'s wrapper for `get_passwords` sends protocol choice `4` followed
by just a username:

```python
def get_passwords(conn, username):
    output = conn.run_choice("4", [(b"  username : ", username)])
    ...
```

`db.c`'s handler does the same — looks up the user by name and dumps
every password row for them, with no notion of "is this caller allowed
to see this user's data":

```c
int get_passwords(const char *username)
{
    User *u = find_user_by_username(username);
    ...
    printf("[%d] name=%s password=%s size=%zu\n", ...);
}
```

Since port 8080 is published on the host, we can skip the app (port 1337)
and its JWT/DSA login entirely and just talk to the DB directly:

```
$ nc localhost 8080
...
choice > 4
  username : flag4_user
[0] name=google.com password=4a13e59...b338cb6...ebc8b size=128
...
[11] name=flag4 password=dfb84c6785f61ae5b03b691915aa2548efef6a814448c09847ac19cb19a9c96f size=64
COUNT 12
```

This hands us every ciphertext, including `flag4`, still fully E2E
encrypted under `flag4_user`'s private cipher key — which we don't know.

### Step 2: The "custom cipher" is a weak 3-round Feistel network

```python
class Cipher:
    def __init__(self, key):
        self.coeffs = [key]
        self.N = 10
        self.ROUNDS = 3
        self.P = 2**128 + 51
        for _ in range(self.N):
            self.coeffs.append(int.from_bytes(md5(self.coeffs[-1].to_bytes(16, "big")).digest(), "big"))

    def f(self, x):
        return sum(self.coeffs[i]*pow(x, i, self.P) for i in range(self.N+1)) % self.P

    def encrypt_block(self, m):
        l, r = m >> 128, m % 2**128
        for _ in range(self.ROUNDS):
            l, r = r, (l + self.f(r)) % self.P
        return l << 128 | r
```

`f` is a public-form degree-10 polynomial over `Z_P` (`P` prime); only its
11 coefficients are secret. Passwords are padded to a multiple of 32
bytes and encrypted in ECB, one 32-byte (256-bit) block at a time, split
into two 128-bit halves `(l, r)`.

Expanding 3 rounds of `l, r = r, (l + f(r)) % P` symbolically for a
plaintext block `(l0, r0)` and its ciphertext `(L, R)` gives:

```
l1 = r0
r1 = l0 + f(r0)
l2 = r1 = l0 + f(r0)
r2 = l1 + f(r1) = r0 + f(l0 + f(r0))
l3 = r2 = r0 + f(l0 + f(r0))          =  L
r3 = l2 + f(r2) = (l0 + f(r0)) + f(L)  =  R
```

From the `r3` line:

```
R = l0 + f(r0) + f(L)
=>  f(r0) + f(L) ≡ R - l0   (mod P)
```

Because `f` is *linear in its unknown coefficients* (`f(x) = Σ cᵢxⁱ`,
`x` known), every known `(l0, r0) → (L, R)` block pair yields one linear
equation in the 11 unknowns `c0..c10`, with all the `xⁱ` "basis" terms
computable from data we already have. 11 independent pairs are enough to
solve for `f` exactly via Gaussian elimination over `Z_P` — no key, no
MD5 hash-chain inversion required.

Verified this relation against the real `Cipher` class with a random key
before relying on it:

```python
>>> f(r0) + f(L) == R - l0   (mod P)   # True, for every trial
```

### Step 3: Harvest known plaintexts and solve

`dispatcher_flag4.py` saves 11 passwords whose plaintexts are hardcoded
in the script itself (`google.com`, `facebook.com`, ... `stackoverflow.com`),
each exactly 32 ASCII bytes, so each pads to exactly 2 blocks (the real
password + one full 32-byte padding block of value `0x20`). That's
`11 × 2 = 22` known plaintext/ciphertext block pairs — all encrypted
under the *same* session key, since they're all saved in the one
`dispatcher_flag4.py` login session.

(Sanity check: the second, all-padding block is identical plaintext for
every entry, and indeed all 11 of their ciphertext second-halves come
back byte-for-byte identical — confirming ECB + shared key, as expected.)

22 equations, 11 unknowns → solve, recover `f`, then decrypt is just
running the Feistel rounds backward with the recovered `f`:

```python
import socket, re

DB_HOST, DB_PORT = "localhost", 8080
P = 2**128 + 51
N = 10  # degree

known_passwords = [
    ('google.com', '7c7aa73b2912d6c56b06ed2fc94914f0'),
    ('facebook.com', '557e5301cab14290574d6eceb9d1341f'),
    ('twitter.com', '2b4800d33a398ddc54f6faa4647f0989'),
    ('github.com', 'f769f96061fc1d3f8e83d487b0582f9c'),
    ('linkedin.com', '5767c60bb037dbba6945fcf4dabec30c'),
    ('instagram.com', '41f561335e451ffea322afe8a9143be2'),
    ('netflix.com', '94fa22e54246c90874f6e348e95b978b'),
    ('spotify.com', '4ea270260f156d9714c512b1fdf2659c'),
    ('paypal.com', '4879f35403bdfb3aef62d9f4c27e998a'),
    ('amazon.com', '10488a325e5f0dd9032915a6f0f7fa58'),
    ('stackoverflow.com', 'd1c8e5a9b2f0c3e4a7f6b8d9c1e2f3a4'),
]

def pad(data):
    padding_length = 32 - (len(data) % 32)
    return data + bytes([padding_length] * padding_length)

# 1. connect straight to the DB service (port 8080, exposed by docker-compose).
#    get_passwords (choice 4) only takes a username - no session/token/signature
#    is required at that layer, so any client on the network can read any
#    account's (encrypted) passwords directly, bypassing the app/JWT layer.
def recvuntil(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

s = socket.create_connection((DB_HOST, DB_PORT), timeout=5)
recvuntil(s, b"choice > ")
s.sendall(b"4\n")
recvuntil(s, b"username : ")
s.sendall(b"flag4_user\n")
s.settimeout(2)
out = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        out += chunk
except socket.timeout:
    pass
s.close()

stored = {}
for m in re.finditer(r"name=(\S+)\s+password=([0-9a-f]+)\s+size=\d+", out.decode()):
    stored[m.group(1)] = m.group(2)

# 2. build known (plaintext_block, ciphertext_block) pairs
pairs = []  # (l0, r0, L, R)
for name, plaintext in known_passwords:
    ct_hex = stored[name]
    ct_bytes = bytes.fromhex(ct_hex)
    pt_bytes = pad(plaintext.encode())
    assert len(ct_bytes) == len(pt_bytes) == 64
    for i in range(0, 64, 32):
        pt_block = pt_bytes[i:i+32]
        ct_block = ct_bytes[i:i+32]
        m = int.from_bytes(pt_block, "big")
        c = int.from_bytes(ct_block, "big")
        l0, r0 = m >> 128, m % (2**128)
        L, R = c >> 128, c % (2**128)
        pairs.append((l0, r0, L, R))

print(f"[+] collected {len(pairs)} known plaintext/ciphertext block pairs")

# 3. Build linear system: sum_i c_i * (r0^i + L^i) = R - l0  (mod P)
rows = []
rhs = []
for (l0, r0, L, R) in pairs:
    row = [pow(r0, i, P) + pow(L, i, P) for i in range(N + 1)]
    row = [x % P for x in row]
    rows.append(row)
    rhs.append((R - l0) % P)

# Gaussian elimination mod P (field)
n_unknowns = N + 1
n_eq = len(rows)
M = [rows[i][:] + [rhs[i]] for i in range(n_eq)]

def modinv(a, p):
    return pow(a, p - 2, p)

pivot_row = 0
for col in range(n_unknowns):
    piv = None
    for r in range(pivot_row, n_eq):
        if M[r][col] % P != 0:
            piv = r
            break
    if piv is None:
        continue
    M[pivot_row], M[piv] = M[piv], M[pivot_row]
    inv = modinv(M[pivot_row][col], P)
    M[pivot_row] = [(x * inv) % P for x in M[pivot_row]]
    for r in range(n_eq):
        if r != pivot_row and M[r][col] % P != 0:
            factor = M[r][col]
            M[r] = [(M[r][k] - factor * M[pivot_row][k]) % P for k in range(n_unknowns + 1)]
    pivot_row += 1

coeffs = [0] * n_unknowns
for r in range(n_eq):
    row = M[r]
    nonzero_cols = [c for c in range(n_unknowns) if row[c] % P != 0]
    if len(nonzero_cols) == 1:
        coeffs[nonzero_cols[0]] = row[-1] % P

print("[+] recovered coefficients:", coeffs)

def f(x):
    return sum(coeffs[i] * pow(x, i, P) for i in range(N + 1)) % P

# sanity check against known pairs
ok = True
for (l0, r0, L, R) in pairs:
    if (f(r0) + f(L)) % P != (R - l0) % P:
        ok = False
print("[+] sanity check on known pairs:", ok)

ROUNDS = 3
def decrypt_block(c):
    l, r = c >> 128, c % (2**128)
    for _ in range(ROUNDS):
        l, r = (r - f(l)) % P, l
    return (l << 128) | r

def unpad(data):
    padding_length = data[-1]
    if padding_length > 32 or padding_length == 0 or data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

flag_ct = bytes.fromhex(stored["flag4"])
plaintext = b""
for i in range(0, len(flag_ct), 32):
    block = flag_ct[i:i+32]
    c_int = int.from_bytes(block, "big")
    m_int = decrypt_block(c_int)
    plaintext += m_int.to_bytes(32, "big")

flag = unpad(plaintext)
print("[+] FLAG4:", flag)
```

```
$ python3 exploit_flag4.py
[+] collected 22 known plaintext/ciphertext block pairs
[+] recovered coefficients: [16506460969676306385881415958087627668, 186923704378923836828591384952719183567, 280854926115709172873617879235322514500, 105173583530177569581707272283012307444, 220588945974525517238160105866229608944, 280432951720500239021223188473718093887, 123703357116146247001714648939546867140, 262901691868445738048523702216699719968, 16915094722975739548279201546028772727, 38703900174264301528025918909328214628, 177374026045410591511453805114845857601]
[+] sanity check on known pairs: True
[+] FLAG4: b'ICO{example_flag4}'
```

**Note:** the exploit never learns the actual key or `flag4_user`'s
password (it derives `f` directly, coefficient-for-coefficient, from
linear algebra over known plaintext), and it never touches the app's
JWT/DSA auth — it only relies on the DB service's missing per-user
authorization on `get_passwords`, plus the algebraic weakness of the
cipher's round function. Against the real scored instance the same
script recovers the true `FLAG4` value unmodified.

## Flag

```
ICO{example_flag4}
```
