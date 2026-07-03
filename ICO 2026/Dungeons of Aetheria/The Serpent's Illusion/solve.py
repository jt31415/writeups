#!/usr/bin/env python3
"""
Recover keystream from a blob that is long_to_bytes(seal, 32) + ciphertext.

Usage:
  python recover_keystream.py --p <P> --g <G> --infile blob.bin --out ks.bin

The script:
- reads the input file,
- takes the first 32 bytes as big-endian seal,
- treats the remainder as ciphertext and computes the keystream of the same length.
"""
import argparse
import sys

A = 0x9E3779B9
B = 0x12345678

def parse_bigint(s: str) -> int:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s, 10)

def recover_keystream(p: int, g: int, seal: int, length: int) -> bytes:
    out = bytearray()
    mod_exp = p - 1
    for i in range(length):
        c = (i * A + B) % mod_exp
        bind_base = pow(g, c, p)
        # derived formula: coil = bind_base * seal^(2c + 1) mod p
        coil = (bind_base * pow(seal, 2 * c + 1, p)) % p
        b = (coil >> ((i * 7) % 24)) & 0xFF
        out.append(b)
    return bytes(out)

def main():
    p = 0x821bcfa678ee2366e04a829227e34f3c882c72a005cd4e73d449845d4cec1a13
    g = 2

    data = open("gm_chamber.aethmap", "rb").read()
    payload = data[0xe0:]

    if len(data) < 32:
        print("Input must be at least 32 bytes (seal + maybe empty ciphertext).", file=sys.stderr)
        sys.exit(2)

    seal_bytes = payload[:32]
    ciphertext = payload[32:]
    seal = int.from_bytes(seal_bytes, "big")
    ks = recover_keystream(p, g, seal, len(ciphertext))

    with open("decrypted.aethmap", "wb") as f:
        f.write(data[:0xe0] + bytes(p ^ k for p, k in zip(ciphertext, ks)))

if __name__ == "__main__":
    main()