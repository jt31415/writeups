import subprocess

xored = list(b'\x33\xaa\xd0\xa4\x42\x65\x74\x95\x66\x6c\xb6\x38\x24\xdb\xc6\x0b\x9a\xfa\xa0\x3b\x9e\x19\x49\x24\xd3\x07\xa7\xdb\x48\x7f\xcd\xdd\x1f\x9d\x24\x97\x33\x2d\xf6\x06\x6d\x12\x4c\xcc\x0f\x71\xd2\x42')

# rev mod3
xor_key = list(bytes.fromhex("1c025261c0"))[::-1]
for i in range(1, 0x2b, 5):
    for j in range(i, i+5):
        xored[j] ^= xor_key[(j-1) % 5]

# rev mod2
decrypted = list(0 for _ in range(0x30))
decrypted[0] = xored[0]
for i in range(1, 0x30):
    decrypted[i] = (xored[i] - i - xored[i-1]) & 0xff
print(" ".join([hex(n)[2:] for n in decrypted]))

# inp_copy = output.copy()
# for i in range(1, 0x30):
#     inp_copy[i] = (i + inp_copy[i - 1] + inp_copy[i]) & 0xff
# print(" ".join([hex(n)[2:] for n in inp_copy]))

# rev mod1
decrypted = decrypted[::-1]
# xored = [n % 256 for n in xored]

print(bytes(decrypted))

with open("/tmp/password", "wb") as f:
    f.write(bytes(decrypted))

# proc = subprocess.run(["/app/password_checker", bytes(output)])
# if proc.returncode == 1:
#     print("success")
# else:
#     print("fail")
