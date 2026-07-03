import re
from pwn import *
import os
from hashlib import sha1, md5
import time
from dist.gui.client import Client, Cipher
from dist.app.db import BinaryDBConnection, get_user
import json

if True:
    IP = "localhost"
    DATABASE_PORT = 8080
    APP_PORT = 1337
else:
    IP = "vaultlock.challs.ico-official.net"
    DATABASE_PORT = 44013
    APP_PORT = 43623

# from app/db.py
def get_db_connection():
    host = os.getenv("BINARY_DB_HOST", IP)
    port = int(os.getenv("BINARY_DB_PORT", DATABASE_PORT))
    timeout = float(os.getenv("BINARY_DB_TIMEOUT", "3.0"))
    return BinaryDBConnection(host, port, timeout=timeout)

# ----------------------------------------------------------------------------------------
# SOLVE START
# ----------------------------------------------------------------------------------------

USERNAME = "flag2_user"

# fill these with the challenge parameters (integers)
p = 145482636923397461551027208559651954303149258608851889694652183758050717178579633605310672246796347902472353542522473915525343724045709089502360738677183303408008337590690549831006572025023009619500871137169125224642328921020102662733437406581174943889190113759870739412218503148336297751875878950760414328619
q = 1163831994178887226445010075499141560949800227939
g = 56859159188459710387263618240727430643849528928801911946226651214359185343766274154621360314738042802139421086117532802813694014962141964120198509538059611686659508161583102212425540742950911131785647410535976809387376365320801618348696151280534200488311706129424193527700062262935454155221213554300069710363

db_conn = get_db_connection()
y = int(get_user(db_conn, USERNAME)[0][1], 16)  # public key = g^x mod p


def forge(p, q, g, y, z):
    # r := (g^z * y mod p) mod q
    r = (pow(g, z, p) * y) % p % q
    s = r % q
    return r, s

def verify(p, q, g, y, z, r, s):
    H = (z * r) % q
    w = pow(s, -1, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r

client = Client(IP, APP_PORT)

actual_timestamp = int(time.time()) // 10
found = False
for timestamp in range(actual_timestamp + 1, actual_timestamp - 10000, -1):
    message = f"{USERNAME}:{timestamp}".encode()
    z = int(sha1(message).hexdigest(), 16)  # value such that H(m) = z * r (mod q or as given)
    r, s = forge(p, q, g, y, z)

    # from gui/client.py, but without actual r,s generation
    request = {
        "action": "login_user",
        "username": USERNAME,
        "r": r,
        "s": s
    }
    response = client._send(request)
    try:
        if not "error" in response:
            client.token = response.get("token")
            client.cipher = Cipher(key=int(md5(client.auth.x.to_bytes(20, "big")).hexdigest(), 16))
            found = True
            break
    except (json.JSONDecodeError, AttributeError):
        client.token = None

if found:
    print(f"Logged in successfully with timestamp {timestamp}")
    print(client.get_notes())