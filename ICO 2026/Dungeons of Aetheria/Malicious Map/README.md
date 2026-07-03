---
title: "Malicious Map"
ctf: "ICO 2026"
task: "Dungeons of Aetheria"
date: 2026-06-30
category: pwn
difficulty: hard
points: 40
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# Malicious Map

## Summary

A TCP service (`aetheria_server`, Ubuntu 20.04 / glibc 2.31, PIE) parses `.aethmap`
uploads and lets you create/patch/release/scribe/seal "maps". Two bad habits combine
into full control-flow hijack:

1. A **format string** in the upload handler (`dprintf(fd, m->author_name, ...)`)
   leaks a function pointer on every upload — no corruption required.
2. An **off-by-one null-byte** bug in `PATCH` lets us forge a heap chunk, trick
   `free()` into an unsafe backward consolidation (Poison Null Byte / House of
   Einherjar), and land a `Scribe` struct's function pointer inside our own writable
   buffer — letting us redirect it to the binary's flag-printing function.

> The same `dprintf` bug on its own leaks an environment variable and solves the
> sibling challenge **Archivist's Slip** (the "easy" flag). This challenge chains
> both bugs for RCE-style control-flow hijack.

## Solution

### Step 1: Leak a function pointer via the format string

`parse_map` in `server.cpp` does:

```cpp
dprintf(fd, m->author_name, puts, malloc, free, husk_ritual, archive_note());
```

`author_name` is fully attacker-controlled (copied straight from our upload). Using
`%4$p` leaks `husk_ritual`'s address directly — no separate libc/PIE leak needed
(glibc requires positional args `%1$`–`%3$` to also be referenced, so we include them
even though we don't need their values).

### Step 2: Off-by-one null byte in PATCH

```cpp
static void patch_scroll(int fd, HostedMap *m, size_t n) {
    if (n > SCROLL_SIZE + 8) n = SCROLL_SIZE + 8;
    char buf[SCROLL_SIZE + 8];
    if (!read_exact(fd, buf, n)) return;
    memcpy(m->scroll, buf, n);
    m->scroll[n] = 0;   // <-- off-by-one NULL write
}
```

`SCROLL_SIZE + 8` (`0x4f8`) is exactly `malloc(SCROLL_SIZE)`'s real usable size, so the
`memcpy` itself is "safe" by glibc's accounting — but the trailing `m->scroll[n] = 0`
writes one extra byte, landing on the low byte of the **next** chunk's (`wall`'s) size
field and clearing its `PREV_INUSE` bit.

### Step 3: Forge a chunk and trigger an unsafe unlink

With `wall`'s `PREV_INUSE` cleared, calling `RELEASE` (`free(wall)`) makes glibc believe
the *previous* chunk (`scroll`) is free, and backward-consolidates using the `prev_size`
field we also control (the last 8 bytes of our `PATCH` payload). We forge a fake chunk
**entirely inside `scroll`'s own buffer**:

- fake size `0x300` (kept under `0x400` so it's treated as "small" — large chunks need
  extra `fd_nextsize`/`bk_nextsize` checks we'd also have to satisfy)
- self-referential `fd`/`bk` values that pass glibc's safe-unlink check
  (`fd->bk == p && bk->fd == p`)

After consolidation, the resulting larger free chunk *starts inside `scroll`*. The next
`SCRIBE` command (`malloc(0x40)` for the `Scribe{target, limit, seal}` struct) gets
carved from that free chunk and lands at a known offset inside `scroll` — so our **own
`scroll` buffer now overlaps the live `Scribe` struct**.

### Step 4: Overwrite `seal` and trigger it

A second, ordinary `PATCH` writes `husk_ritual`'s leaked address into the `seal` field
of the now-overlapping `Scribe`. `SEAL` then calls `scribe->seal(...)`, which is
`husk_ritual()`:

```cpp
extern "C" int husk_ritual(const void *, size_t, int *, int *) {
    (void)!system("cat /flag.txt");
    return 0;
}
```

Its output goes straight back over the connection (stdout is `dup2`'d to the socket).

### Full solver

See [`solve.py`](solve.py). From a fresh connection to printed flag:

```
[+] husk_ritual leaked at 0x55768a561588
[*] scroll=0x5576bfd33d20 wall=0x5576bfd34220 (diff=0x500)
[*] patch1: b'patched\n> '
[*] release: b'wall released\n> '
[*] scribe resp: b'scribe=0x5576bfd33f20\n> '
[*] patch2: b'patched\n> '
[*] seal resp: b'FLAG{final_verification_run}\nsealed\n> '
[+] FLAG: FLAG{final_verification_run}
```

Run against the live service unmodified — only `HOST`/`PORT` need to change.

## Flag

```
ICO{...}
```
