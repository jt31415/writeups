#!/usr/bin/env python3
"""
Solve script for Aetheria Golden Key challenge.
Statically recovers the flag from aetheria_client_tutorial binary.
"""

import struct

BINARY = "aetheria_client_tutorial"

with open(BINARY, "rb") as f:
    data = f.read()

# --- Step 1: Recover golden key by inverting the 4-round S-box cipher ---

keys_raw = data[0x14a40:0x14a40 + 64]
sbox     = data[0x14a80:0x14a80 + 256]
inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

keys = [list(keys_raw[k * 16:(k + 1) * 16]) for k in range(4)]

# Expected 16-byte output after forward transform (from binary constants at 0xe817)
expected = list(bytes.fromhex("b950733e437cb14177f6cf660903d40f"))

def inv_prefix_xor(state):
    state = list(state)
    for i in range(15, 0, -1):
        state[i] ^= state[i - 1]
    return state

def inverse_transform(state):
    state = list(state)
    for k in range(3, -1, -1):
        state = inv_prefix_xor(state)
        for i in range(16):
            state[i] = inv_sbox[state[i]] ^ keys[k][i]
    return state

golden_key_bytes = bytes(inverse_transform(expected))
golden_key_hex   = golden_key_bytes.hex()  # 32-char hex string = the console argument

# --- Step 2: Decrypt the 31-byte flag body from the binary's rodata table ---

table  = data[0x147c0:0x147c0 + 31]
body   = bytes(((i * 17 + 93) & 0xff) ^ table[i] for i in range(31))
# body == b"g0ld3n_k3y_unl0cks_d3v_tr34sur3"

# --- Step 3: Compute 24-bit hash suffix (FNV-1a of "rev|" + golden_key_hex) ---

h     = 0xcbf29ce484222325
prime = 0x100000001b3
for b in (b"rev|" + golden_key_hex.encode()):
    h ^= b
    h  = (h * prime) & 0xffffffffffffffff

bits_0_31  =  h         & 0xffffffff
bits_24_55 = (h >> 24)  & 0xffffffff
bits_48_63 = (h >> 48)  & 0xffffffff
hash_24    = (bits_0_31 ^ bits_24_55 ^ bits_48_63) & 0xffffff

# --- Assemble flag ---
flag = f"ICO{{{body.decode()}_{hash_24:06X}}}"
print(flag)
