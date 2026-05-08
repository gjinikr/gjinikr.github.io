---
layout: post
title: "SHC 2026: Bedrock Bank - Android APK RE with Native Constraint Solving"
date: 2026-05-08
tags: [re]
---

## Challenge Overview

**Binary:** `bedrockbank.apk` — Android app
**Goal:** Find valid account key in format `BRCK-XXXX-XXXX-XXXX-XXXX`
**Flag:** `dach2026{y4bb4_d4bb4_d00_1t!}`

## Recon

Unpacked the APK. Interesting components:
- `KeyValidator.smali` — Kotlin-side preprocessing and format checking
- `NativeValidator.smali` — JNI wrapper with two native methods
- `libbedrockbank.so` — native C validation (the real logic)

## Validation Flow

```
User key "BRCK-g1-g2-g3-g4"
     ↓
KeyValidator.validateFormat        (regex sanity)
     ↓
KeyValidator.performFullValidation
     →  crc         = crc16(g1, g2)
     →  g3'         = g3 XOR 0xA5C3
     →  interleaved = interleave(g1, g2)
     →  mixedToken  = mix(g1, g2, g3)
     ↓
NativeValidator.validateFull(g1, g2, crc, g3', interleaved, g4, mixedToken)
     ↓ (if true)
NativeValidator.deriveFlag(g1, g2, g3, g4, kotlinToken)
     ↓
"dach2026{...}"
```

## Reversing the Kotlin Side

Three helper functions translated from smali:

**computeChecksum(g1, g2):** CRC-16/CCITT-FALSE over `(g1 << 16) | g2`, poly `0x1021`, init `0xFFFF`.

**interleaveValues(g1, g2):** Weaves nibbles of g1 and g2 alternately into a 32-bit word, then rotates left 5 bits.

**mixValues(g1, g2, g3):** 7-round mixer:

```python
state = 0x5A5A5A5A ^ g1
for r in range(7):
    state = rotl32(state, 3)
    state = state ^ (g2 + r)
    state = state + rotr32(g3, r*2)
    state = state ^ ((state >> 16) | (state << 16))  # halves-swap XOR
```

**Gotcha:** Dalvik's `shr-int` is arithmetic (sign-extending). My first Python port was wrong on this detail. Used Frida to calibrate against real JVM output.

## Reversing the Native Side (Ghidra)

Two exports: `validateFull` and `deriveFlag`.

Notable internal functions:
- `FUN_00010f10(x)` — `~(x*x + x) & 1` — always returns 1 (decoy)
- `FUN_00010d70()` — reads `/proc/self/status`, checks `TracerPid: 0` (anti-debug)

### validateFull Constraints

After mapping every `FUN_00010e40(x, y) != 0` as `x == y`:

1. Weighted nibble sum on g1 == 0x5E
2. `popcount((g1 ^ g2) & 0xFFFF) == 5`
3. `crc(g1, g2) == 0xC430`
4. `rotl16(g3', 3) XOR 0xDEAD == 0xF646`
5. `mixedToken == 0x12788169`
6. `g4` derived from g1, g2, crc, interleaved

Constraint 4 solves immediately:

```
rotl16(g3', 3) = 0xDEAD XOR 0xF646 = 0x28EB
g3' = rotr16(0x28EB, 3) = 0x651D
g3  = g3' XOR 0xA5C3 = 0xC0DE
```

**g3 = 0xC0DE.** The "code" in the "code block." Nice touch.

### deriveFlag — The Second Gate

This was the key anti-bypass technique: `deriveFlag` computes flag bytes from g1..g4, then runs a weighted sum integrity check. If wrong, returns `"INVALID"`. So `dach2026{INVALID}` is returned for any wrong key — even if you bypass `validateFull`.

**This forces you to find the real key.** No shortcuts.

## Solving for the Key

Strongest constraint is C5: `mix(g1, g2, 0xC0DE) == 0x12788169` — a 32-bit equation in (g1, g2).

Calibrated `mixValues` against the real JVM via Frida:

```javascript
var m = Class.forName('com.bedrockbank.app.KeyValidator')
             .getDeclaredMethod('mixValues', ...);
m.setAccessible(true);
// mixValues(0x1234, 0x5678, 0xC0DE) = 0x55E38A3C
```

Brute-forced C5 in C (2^32 iterations, ~45 seconds):

```c
for (uint32_t g1 = 0; g1 < 0x10000; g1++)
    for (uint32_t g2 = 0; g2 < 0x10000; g2++)
        if (mix_values(g1, g2, 0xC0DE) == 0x12788169)
            printf("%04X %04X\n", g1, g2);
```

Yielded 2560 candidate pairs. Filtered through nibsum + popcount + CRC — exactly one survivor.

Computed g4 from the C6 formula, assembled the key, entered it.

```
ACCOUNT KEY: BRCK-XXXX-XXXX-C0DE-XXXX

App response: Yabba Dabba Doo! Vault Opened!
FLAG: dach2026{y4bb4_d4bb4_d00_1t!}
```

## Key Takeaways

- **Always calibrate against ground truth.** One Frida reflective call saved hours of wrong-track debugging on the signed-shift bug.
- **The second gate pattern is a clean anti-bypass technique.** Splitting "does the key validate" from "does the output look right" forces attackers to find the real solution.
- **Brute + filter beats analytical inversion.** C5 has ~2560 collisions in 2^32 space; the other constraints prune to one. Pragmatic and fast.
- **Decoy constraints exist.** `FUN_00010f10` always returns 1 — looks like a check, does nothing.
