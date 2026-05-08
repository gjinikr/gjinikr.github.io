---
layout: post
title: "SHC 2026: DinoConfigurator - .NET RE with a Custom LCG"
date: 2026-05-08
tags: [re]
---

## Challenge Overview

**Target:** DinoConfigurator.exe — a Windows .NET WinForms application
**Goal:** Find valid username + password to trigger AES decryption of the flag

## Initial Analysis

Used `file` and `strings` on Linux to identify it as a **.NET assembly**.
Loaded into **ILSpy** (VS Code extension) to decompile.

## Decompiling the Login Logic

In `btnLogin_Click`:

```csharp
Verifier.ValidateUser(username, password);
// If successful — AES-CBC decrypt hardcoded 48-byte array using Password as key
```

## Discovery: Pixel-XOR Verification

Inside `Verifier.VerifySecret` — not a simple string comparison:

- **Embedded image**: `matteo_discardi_tdA2J1uJHew_unsplash`
- For each byte in the secret array, the program uses a `Random` object to pick a pixel coordinate
- Computes a **mask** from the pixel's color channels
- Compares: `secret_byte XOR mask == expected`

## Critical Finding: Custom LCG (DinoRandom)

The program did **not** use `System.Random`. It implemented a custom **Linear Congruential Generator** with hardcoded constants. Standard library random solvers would produce wrong sequences because the math is different.

We had to manually reimplement `DinoRandom` to stay in sync with the program's state.

## Cryptographic Reconstruction

- **Algorithm**: AES-256-CBC
- **IV**: `908194288470cb5d` (16 bytes)
- **Key**: The recovered password string (32 bytes)
- **Ciphertext**: 48-byte array hardcoded in `btnLogin`

## Solution

Wrote a C# solver for the **Mono** runtime that:

1. Re-implemented the `DinoRandom` LCG
2. Loaded the resource image
3. Performed inverse XOR to recover each secret byte
4. Recovered **Username** (seed: 1337) and **Password** (seed: 42)
5. Decrypted AES-CBC — flag: `SHC{...}`

## Key Lessons

- **Static analysis is king**: The custom `Random` class was the pivot point. Missing it would have blocked progress entirely.
- **XOR is reversible**: `A XOR B = C` → `A = C XOR B`. Always.
- **Resource extraction matters**: One bit of image compression difference would break the entire chain.
