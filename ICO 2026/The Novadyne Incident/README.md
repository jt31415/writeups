---
title: "The Novadyne Incident"
ctf: "ICO 2026"
task: "The Novadyne Incident"
date: 2026-06-29
category: mixed
difficulty: unknown
points: "15 / 30 / 25 / 30"
flag_format: "ICO{...}"
author: "jt314"
---

> ℹ️ Read the [contest README](../README.md) first — some challenge names, categories, and mappings are inferred.

# The Novadyne Incident (task overview)

> **Note:** This task has **4 subtasks** (point values 15 / 30 / 25 / 30). **No solve
> scripts or writeups were produced**, so subtask folders were not created. Two subtask
> names are confirmed from the scoreboard log; the other two are unknown.
>
> **Confirmed subtask names (from scoreboard):**
> - **Breach the Operator infrastructure** — web exploitation against the "Nexus" C2
>   operator panel (source in `nexus/`).
> - **Recover the Hidden Notes** — forensics/recovery (likely from the evidence set).
> - (2 further subtasks — names unknown.)
>
> **Provided materials** (not copied here — challenge distributables):
> - `evidence/` — `Updater.exe`, `botan-3.dll`, `traffic.pcapng` (malware + network forensics)
> - `nexus/` — full source of the "Nexus" C2 server (Flask + Svelte web app)

## Flag

```
ICO{...}
```
