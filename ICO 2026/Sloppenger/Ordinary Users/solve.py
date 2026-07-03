import requests
import time


def xor(a, b):
    return bytes(c_a ^ c_b for c_a, c_b in zip(a, b))


NONCE = bytes.fromhex("dd38c6730f0c90601c37332e")
COUNTER = 46  # 45 probably off
RECEIVER_ID = 12  # bob id

BASE = "http://localhost:5000"
s = requests.Session()
data = {
    'username': 'alice',
    'password': 'ordinary_password'
}
s.post(f'{BASE}/login', data=data, allow_redirects=False, timeout=5)
hmac = s.get(f'{BASE}/api/hmac', timeout=5).json()["hmac"]

messages = s.get(f'{BASE}/api/get_messages',
                 params={"uuid": RECEIVER_ID}).json()
flag_ct = bytes.fromhex(messages[19]["ciphertext"])

for i in range(0, len(flag_ct), 16):
    plaintext = NONCE + (COUNTER + i//16).to_bytes(4, "big")
    pkt = {
        "plaintext": plaintext.hex(),
        "protocol": "ECB",
        "receiver_uuid": RECEIVER_ID,
        "sid_hmac": hmac
    }
    s.post(f'{BASE}/api/send_message', json=pkt,
           allow_redirects=False, timeout=5)

    time.sleep(0.2)
    messages = s.get(f'{BASE}/api/get_messages',
                 params={"uuid": RECEIVER_ID}).json()
    E_k = bytes.fromhex(messages[-1]["ciphertext"])[:16]
    print(xor(E_k, flag_ct[i:i+16]))
