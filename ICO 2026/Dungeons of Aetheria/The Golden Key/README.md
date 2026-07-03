---
title: "The Golden Key"
ctf: "ICO 2026"
task: "Dungeons of Aetheria"
date: 2026-06-30
category: reverse
difficulty: medium
points: 20
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# Golden Key

## Summary

A stripped SDL2 game client (`aetheria_client_tutorial`) contains a hardcoded developer console cheat `give GoldenKey` that decrypts and prints the flag without any network connection. Statically recovering the correct 32-hex-char key argument and the two flag components (a fixed XOR-decrypted body and a FNV-1a hash suffix) yields the flag directly.

## Solution

### Step 1: Recon

Running `--dump-map-info` reveals six entities. NPC at entity[1] has custom data:

```
msg=Press backtick for the dev console;
```

`strings` on the binary shows `give GoldenKey`, `Golden Key accepted.\n`, `Invalid Golden Key\n` — none present in the provided source, confirming the tutorial binary has extra developer code not in the game-hacking source.

No network addresses appear in the binary (`AETHERIA_CLAIM_URL`, IP addresses all absent), so the flag is entirely local.

### Step 2: Reverse the dev-console handler

Disassembling `main` around the `rfind("give GoldenKey")` call (offset ~`0x7d90`) reveals three stages:

**Argument validation (`0xe6a0`):**  
Accepts a 32-hex-char argument, parses it into 16 bytes, runs a 4-round cipher (each round: `sbox[byte ^ subkey[i]]` then prefix-XOR of the 16 bytes), and compares the result to two hard-coded 64-bit constants:

```
0x41b17c433e7350b9  0x0fd4030966cff677
→ expected bytes: b950733e437cb14177f6cf660903d40f
```

Inverting the cipher recovers the required argument:

```
58c6231dbe29c729c219eabd6a401d59
```

**Flag body decryption (loop at `0x80b5`):**  
31 bytes at rodata offset `0x147c0` are decrypted with:

```
output[i] = ((i × 17 + 93) & 0xff) ^ table[i]
```

Result: `g0ld3n_k3y_unl0cks_d3v_tr34sur3`

**Hash suffix (FNV-1a fold at `0x8028`):**  
FNV-1a 64-bit is computed over `"rev|" + argument`. The 64-bit hash is folded to 24 bits via XOR of its three 24-bit windows (bits 0–23, 24–47, 48–63), then formatted as 6 uppercase hex digits (digit loop at `0x9b38`).

**Flag assembly (function `0x9a70`):**  
Builds `ICO{` + body + `_` + 6-hex-digit suffix + `}` and prints it.

### Step 3: Solve script

```python
#!/usr/bin/env python3
import struct

with open("aetheria_client_tutorial", "rb") as f:
    data = f.read()

# Invert the 4-round cipher to recover the golden key
keys_raw = data[0x14a40:0x14a40 + 64]
sbox     = data[0x14a80:0x14a80 + 256]
inv_sbox = [0] * 256
for i in range(256): inv_sbox[sbox[i]] = i
keys = [list(keys_raw[k*16:(k+1)*16]) for k in range(4)]
expected = list(bytes.fromhex("b950733e437cb14177f6cf660903d40f"))

def inv_prefix_xor(s):
    s = list(s)
    for i in range(15, 0, -1): s[i] ^= s[i-1]
    return s

def invert(state):
    for k in range(3, -1, -1):
        state = inv_prefix_xor(state)
        state = [inv_sbox[state[i]] ^ keys[k][i] for i in range(16)]
    return state

golden_key = bytes(invert(expected)).hex()  # 32-char hex

# Decrypt flag body from rodata table
table = data[0x147c0:0x147c0 + 31]
body  = bytes(((i*17 + 93) & 0xff) ^ table[i] for i in range(31))

# FNV-1a hash of "rev|" + key → fold to 24 bits
h = 0xcbf29ce484222325
for b in (b"rev|" + golden_key.encode()):
    h ^= b; h = (h * 0x100000001b3) & 0xffffffffffffffff
hash_24 = (h ^ (h>>24) ^ (h>>48)) & 0xffffff

print(f"ICO{{{body.decode()}_{hash_24:06X}}}")
```

To make the binary itself print the flag (requires a display):

```bash
./aetheria_client_tutorial --offline tutorial_chamber.aethmap
# Press backtick, type: give GoldenKey 58c6231dbe29c729c219eabd6a401d59
# Flag is printed to stdout
```

## Flag

```
ICO{g0ld3n_k3y_unl0cks_d3v_tr34sur3_6C4C24}
```
