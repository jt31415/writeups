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
