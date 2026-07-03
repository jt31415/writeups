---
title: "PsyDuck Forum - Portal"
ctf: "ICO 2026"
task: "Psyduck fantasy"
date: 2026-06-30
category: web
difficulty: medium
points: 25
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../../README.md) first — some challenge names, categories, and mappings are inferred.

# PsyDuck Forum - Portal

> **Note:** SSTI-style /api/config reset leaks the Flask secret_key, then a forged session + malicious pickle/zip-slip upload yields RCE and the flag. Full chain in solve.py; a prose writeup was not authored.

## Flag

```
ICO{...}
```
