---
title: "Archivist's Slip"
ctf: "ICO 2026"
task: "Dungeons of Aetheria"
date: 2026-06-30
category: pwn
difficulty: easy
points: 15
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# Archivist's Slip

## Summary

The `aetheria_server` TCP service (Ubuntu 20.04 / glibc 2.31, PIE) parses `.aethmap`
uploads. Its upload handler has a **format-string bug**: the attacker-controlled
`author_name` is passed straight to `dprintf` as the format argument. No heap
corruption is needed — a single crafted `UPLOAD` leaks server memory, including an
environment variable that holds the flag.

> The same bug is also the entry point for the harder sibling challenge
> **Malicious Map**, which additionally chains an off-by-one heap bug for full
> control-flow hijack. Here we only need the leak.

## Solution

The vulnerable call in `parse_map` (`server.cpp`):

```cpp
dprintf(fd, m->author_name, puts, malloc, free, husk_ritual, archive_note());
```

`author_name` comes verbatim from our upload, so we have full format-string control.
The 5th vararg is `archive_note()`:

```cpp
static const char *archive_note() {
    const char *note = getenv("AETHERIA_ARCHIVE_NOTE");
    return note && *note ? note : "LOCAL_AETHERIA_ARCHIVE_NOTE";
}
```

Referencing `%5$s` (instead of `%5$p`) dereferences that pointer and prints the
environment variable's contents directly back over the connection — in one `UPLOAD`,
with no `RELEASE`/`SCRIBE`/`PATCH`/`SEAL` dance at all. On the live service
`AETHERIA_ARCHIVE_NOTE` holds the flag.

### Full solver

See [`solve.py`](solve.py). Example run against a local target with
`AETHERIA_ARCHIVE_NOTE` set to a test value:

```
[*] raw response: b'uploaded by 0x7f3f...0x5565....FLAG{rerun_check_2}\nmap 1 stored\n> '
[+] AETHERIA_ARCHIVE_NOTE leaked: FLAG{rerun_check_2}
[+] FLAG: FLAG{rerun_check_2}
```

## Flag

```
ICO{...}
```
