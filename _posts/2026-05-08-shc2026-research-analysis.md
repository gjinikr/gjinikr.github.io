---
layout: post
title: "SHC 2026 Qualifier: Cross-Challenge Structural Analysis"
date: 2026-05-08
tags: [re, pwn, crypto, web, misc]
---

A post-competition analysis of the Swiss Hacking Challenge 2026 Qualifier. Across twelve challenges spanning binary exploitation, reverse engineering, cryptography, web security, and miscellaneous categories, I identified recurring design patterns, deliberate deception techniques, architectural security weaknesses, and novel technical constructs worth documenting.

This is not a collection of individual writeups — those are published separately. This is a meta-level analysis of how the challenges were built, what made them interesting, and how they could have been hardened.

---

## Challenge Vulnerability Matrix

| Challenge | Category | Primary Vulnerability | Key Technique |
|---|---|---|---|
| Base Onion | Crypto/Misc | Multi-layer encoding | Alphabet fingerprinting + XOR |
| DinoConfigurator | RE | Custom PRNG (LCG) | Static .NET decompilation + inverse XOR |
| Dino Vault | Crypto | RSA shared prime factor | GCD factorization attack |
| Punky Hash | Crypto | Modular knapsack (linear hash) | LLL lattice reduction + Babai CVP |
| Stegosaurus | Misc | LSB steganography + XOR sharing | PNG IDAT extraction + C2 emulation |
| Grafasaurus | Web | COPY FROM PROGRAM RCE | PostgreSQL superuser + default creds |
| Canopysaurus | PWN | Heap UAF — function ptr hijack | UDS/CAN framing + tcache reuse |
| Jurassic Stack Park | PWN | Stack overflow + weak cookie | PID-seeded srand + ret2func |
| PlumberHub | Misc | u64 integer overflow (Rust) | Wrap arithmetic bypasses cost gate |
| ZIPPER | Crypto/Misc | Linear hash (matrix product GF(p)) | Matrix inversion + gzip FEXTRA embed |
| DinOData | Web | OData lambda IDOR | Navigation property auth bypass |
| Bedrock Bank | RE | Multi-constraint native RE | Frida calibration + C brute force |

---

## 1. Information Leak Primitives

A consistent structural pattern across SHC2026 was the intentional embedding of information leaks that enable otherwise-impossible attacks.

### 1.1 Process ID Leak — Deterministic PRNG Prediction

Jurassic Stack Park printed the server process PID in its startup banner:

```
Terminal PID    : 22
```

The binary seeded glibc's `rand()` with the PID via `srand(getpid())`, then stored the first `rand()` output as a stack "cookie." Because the binary was compiled without PIE, ASLR had no effect, and the seed was fully deterministic from the leaked value. Reproduction required only:

```python
import ctypes
_libc = ctypes.CDLL('libc.so.6')
def predict_rand(pid):
    _libc.srand(pid)
    return _libc.rand()
```

This is a well-known pedagogical pattern: a value that appears to be a security control is undermined by an information leak that makes it fully predictable. Process IDs must never be used as entropy sources.

### 1.2 Oracle Leak — Secret Matrix Recovery (ZIPPER)

ZIPPER's server responded to incorrect submissions with the full hash of the submitted file:

```
Wrong hash: 3a7f8c2d1e...
```

The hash function computes `H(m) = I · S₀ · S₁ · … · Sₙ · S_pad` where `I` is a secret 4×4 matrix over GF(4919) fixed per server process. A single probe with a known input allows algebraic recovery of `I`:

```python
# A_response = I · B · S_pad
# Therefore:
I = A_response * (B * S_pad).inverse()
```

Once `I` is recovered, forging any target hash requires only matrix algebra. This is a textbook chosen-plaintext attack enabled by verbose error responses.

### 1.3 Debug Symbols + No-PIE — Static Address Disclosure

Canopysaurus was compiled with `-g` (debug symbols) and `-no-pie`, making the address of every function directly readable:

```bash
nm --defined-only ./ecu_sim | grep reset_code
# 00000000004014bc T reset_code
```

In a real exploitation scenario, an attacker needs to leak an address before hijacking a function pointer. Here, the address was handed to them in the binary. The `-g` flag further eliminated the need to recover function names through disassembly heuristics.

### 1.4 JWT Claim Exposure — Identity Enumeration

DinOData's JWT tokens contained a `nameidentifier` claim directly encoding the server-assigned `ScientistId`. While the exploit did not ultimately depend on IDOR via this value, it confirmed the attack hypothesis before exploitation began. Internal database IDs should not be surfaced in authentication tokens.

---

## 2. Red Herring Taxonomy

SHC2026 demonstrated sophisticated use of deliberate misdirection. I identify five distinct categories.

### Type I — Security-Looking Controls That Do Nothing

**Canopysaurus: SecurityAccess (0x27)**

The UDS SecurityAccess service presented a seed/key ceremony with formula `seed ^ 0xCAFEBABE`. It appeared to gate elevated privileges. In reality, none of the services in the exploit chain checked `session.security_level` — only `session_type != SESSION_DEFAULT`. A single `DiagnosticSessionControl (0x10 0x03)` was sufficient. The SecurityAccess ceremony was pure theater.

**Bedrock Bank: FUN_00010f10**

Ghidra decompilation produced a function used in a conditional check. Static analysis revealed it computes `~(x*(x+1)) & 1` — which equals 1 for all inputs, because `x*(x+1)` is always even. The constraint always passes. Identifying this as a decoy saved significant time.

### Type II — Real Primitives That Lead Nowhere

**Canopysaurus: Partial RELRO / GOT Writability**

The binary had a writable GOT. An attacker noticing this might pursue a GOT overwrite. The UAF function pointer hijack was cleaner and more direct. The GOT primitive was real — just not the intended path.

### Type III — Algorithmic Complexity as Cognitive Noise

**PlumberHub: Supply-Chain Package Substitution**

`Cargo.lock` included two packages that do not exist in the real crates.io ecosystem: `zmij` and `serde_core`. These triggered a supply-chain analysis thread. The actual vulnerability was integer overflow in the cost calculation — entirely unrelated to serialization. The fake packages were pure noise designed to send analysts down a dependency audit path.

**Stegosaurus: Innocent Module Exports**

The `dinoraww` Node.js module exported several functions with legitimate-sounding names. The real backdoor was loaded via a single `require('./lib/loader.js')` at the end of `index.js`. The module's apparent innocuousness required reading to the very end of the file.

### Type IV — Near-Solutions That Almost Work

**PlumberHub: Nested Async Delegation**

A plausible attack involved nesting the expensive contractor hire inside delegated async work, so a cheap outer contractor would absorb the bill after the flag was already printed. The structure was logically sound:

```
hire-contractor 1                       # cheap, affordable
delegate-work task1 4 1
  hire-contractor 13790000000           # ancient, expensive
  delegate-work task2 1 13790000000
    clear-obstruction eldritch-presence FLAG
  wait-for-delegated-work task2
wait-for-delegated-work task1
run
```

This failed because the cheap contractor went bankrupt paying the bill before the summary propagated. The u64 integer overflow was the intended path.

### Type V — Anti-Bypass Traps

**Bedrock Bank: deriveFlag Weighted Sum Gate**

The most elegant anti-bypass mechanism in the challenge set. `deriveFlag` computes flag bytes from `g1..g4` via a Feistel-style loop, then applies a weighted sum integrity check:

```python
flag_bytes = derive(g1, g2, g3, g4, kotlinToken)
if sum_weighted(flag_bytes) == 0x376F:
    return flag_bytes   # real flag
else:
    return "INVALID"    # literal C string — still inside flag format
```

Bypassing `validateFull` via Frida while passing wrong values still produces `dach2026{INVALID}`. The challenge author split validation into two independent gates: does the key pass format checking, and does the derived output satisfy an integrity predicate. This forces the attacker to find the mathematically correct key. No shortcuts.

---

## 3. Cryptographic Construction Analysis

### 3.1 Custom PRNG in Security-Critical Context (DinoConfigurator)

DinoConfigurator implemented a custom LCG (`DinoRandom`) instead of `System.Random`. Both are insecure for cryptographic purposes, but the custom LCG introduced a subtler problem: any analysis tool assuming `System.Random` would produce incorrect sequences and fail silently. The LCG parameters were hardcoded in the binary, making the state deterministic from seeds 1337 and 42 once recovered via static analysis. Security-by-obscurity via custom PRNG: the obscurity added analysis time but zero actual security.

### 3.2 Shared State Across Sessions (Dino Vault)

The RSA-like scheme used `N = p × q` with `p` fresh per request but `q` fixed for the object lifetime. The attack:

```
N₁ = p₁ × q   (request 1)
N₂ = p₂ × q   (request 2)

gcd(N₁, N₂) = q     # immediate factorization
p₁ = N₁ / q         # complete factorization
φ  = (p₁-1)(q-1)   # Euler totient
d  = e⁻¹ mod φ     # private key recovered
```

This mirrors the 2012 Heninger et al. "Mining Your Ps and Qs" finding — approximately 0.2% of real TLS certificates shared a prime factor due to low-entropy key generation. Both primes must be freshly generated per session, without exception.

### 3.3 Linear Hash (ZIPPER)

ZIPPER's hash computed a product of 4×4 matrices over GF(4919). A secure hash requires the avalanche effect — one bit flip should randomize ~50% of output bits. Matrix multiplication over a finite field satisfies none of these properties. The linearity enables:

- Second preimage: given m₁, trivially find m₂ such that H(m₁) = H(m₂)
- Chosen-prefix forgery: construct any prefix, solve algebraically for a suffix
- Length-extension: append arbitrary blocks while maintaining a target hash

The intended solution required recognizing this and exploiting it via matrix inversion — an algebraic operation, not brute force.

### 3.4 Modular Knapsack with Small Coefficients (Punky Hash)

The modular knapsack `hash = Σ(fᵢ × xᵢ) mod p` is NP-hard in general, but this instance was solvable via LLL lattice reduction because the coefficient size (8-bit, max 255) was vastly smaller than the modulus (137-bit prime). The ratio of solution norm to modulus fell below the threshold at which LLL succeeds with high probability. Babai's nearest-plane algorithm found the preimage in under one second against a search space of 256^16. When you see a modular linear combination of small unknowns, think lattice.

---

## 4. Architectural Authorization Failures

### 4.1 Controller-Level vs. Data-Level Authorization (DinOData)

DinOData filtered Note access at the ASP.NET controller layer by JWT-authenticated ScientistId. This correctly prevented direct Note endpoint access. However, the public Scientist endpoint's OData `$filter` was not sandboxed against navigation property traversal:

```
GET /odata/Scientist?$filter=Notes/any(n:startswith(n/Content,'dach2026{'))
# → Returns Ellie Sattler if her Note starts with 'dach2026{'
```

The `any()` lambda traverses the Notes navigation property via ORM — without invoking the Note controller, without triggering the JWT filter. The authorization boundary was at the wrong layer.

> **Root cause:** Authorization enforced at the service layer is bypassed whenever data can be accessed through an alternative code path that does not route through that service. True data-level security requires row-level policies applied at the ORM query generation layer, not the API handler layer.

Blind boolean extraction recovered the flag character by character in ~50 requests using `startswith`.

### 4.2 Superuser Datasource + Feature Exploitation (Grafasaurus)

Three independent weaknesses combined:

1. **Default credentials** (`admin:admin`) — never rotated, granted full Grafana API access
2. **Superuser datasource** — PostgreSQL connection as `postgres` has unrestricted `COPY FROM PROGRAM`
3. **readOnly flag bypass** — the datasource was marked `readOnly: true` but multi-statement DDL was accepted

The flag was at `/flag` with `--x--x--x` permissions — readable by no user but executable by all. `cat /flag` fails; `COPY g_out FROM PROGRAM '/flag'` captures stdout:

```sql
DROP TABLE IF EXISTS g_out;
CREATE TABLE g_out(t text);
COPY g_out FROM PROGRAM '/flag';
SELECT * FROM g_out;
-- dach2026{Gr4f4na_c0mb1n3d_w1th_d1n0s4ur_d4ta}
```

The execute-only permission was the intended twist — blocking all read attempts while still allowing execution.

---

## 5. Binary Exploitation: Structural Observations

### 5.1 Heap UAF via Automotive Protocol (Canopysaurus)

Wrapping a classic heap UAF in UDS/CAN protocol framing was the most distinctive choice in the challenge set. UDS (Unified Diagnostic Services) is the standard for ECU communication in the automotive industry. Implementing it as the challenge interface required solvers to understand CAN frame structure (16-byte SocketCAN `can_frame`), UDS service codes, and session state before reaching the actual vulnerability.

The struct size collision was deliberate: `dtc_entry_t` and `did_record_t` were both exactly 80 bytes, guaranteeing tcache would return the same chunk without heap feng shui. The critical overlap:

```
did_record.data[4..11]  ==  chunk[+8..+15]  ==  dtc_entry.report_fn
```

Writing to DID data at offset 4 directly overwrites the function pointer. After the RoutineControl write:

```
chunk A (80 bytes):
+00  34 12        → did_record.did_id = 0x1234
+04  FF           → dtc_entry.status = 0xFF (mask match for ReadDTC)
+08  BC 14 40 00  → dtc_entry.report_fn [low 4B] = 0x4014bc
     00 00 00 00  → dtc_entry.report_fn [high 4B]
                 → report_fn = reset_code()
```

ReadDTC triggers `entry->report_fn(entry)` → `reset_code()` → flag.

### 5.2 Stack Layout Precision in 32-bit ret2func (Jurassic Stack Park)

The off-by-one-dword failure mode caught me before the final payload. The symptom: "Specimen registered successfully" printed but connection closed with no flag. No error, no crash output — just EOF.

Root cause: `open_enclosure`'s address was at offset 76 (saved EBP slot) instead of offset 80 (return address slot). The function appeared to complete normally, then jumped to `0x41414141` at offset 80, causing an immediate segfault.

Key constraint in 32-bit cdecl ret2func: hijacking a return address via ret (not call) means no hardware-pushed return address. The called function's own prologue (`push %ebp; mov %esp, %ebp`) sets EBP relative to current ESP, shifting argument positions. Between the cookie at `EBP-0x0C` and the return address at `EBP+0x04` there are exactly three saved dwords: the gap at `EBP-0x08`, saved EBX at `EBP-0x04`, and saved EBP at `EBP+0x00`. Missing any one of them displaces everything.

---

## 6. Novel Technical Constructs

### 6.1 Three-Way LSB XOR Secret Sharing (Stegosaurus)

A 3-of-3 secret sharing scheme using LSB steganography across three PNG images. Each image contributed 32 bytes from the least-significant bit of the blue channel of sequential pixels. XOR of the three shares reconstructed the key:

```
share_1 = extract_lsb_blue(trex.png,   32 bytes)
share_2 = extract_lsb_blue(raptor.png, 32 bytes)
share_3 = extract_lsb_blue(ptero.png,  32 bytes)
kek = share_1 XOR share_2 XOR share_3
```

This is information-theoretically secure for 3-of-3: no single image reveals anything about `kek`. The fourth image (`stego.png`) carried the XOR-encrypted C2 configuration, requiring `kek` for decryption.

### 6.2 gzip FEXTRA as Covert Payload Carrier (ZIPPER)

Python 3.12 tightened gzip parsing to reject non-null bytes after the compressed stream — closing the naive "append data after the stream" approach. The solution exploited the RFC 1952 gzip FEXTRA field: optional metadata in the gzip header that decompressors are required to skip without validation.

Positioning the controllable matrix block inside FEXTRA at a 25-byte-aligned offset made it visible to the hash function while being completely ignored by the decompressor:

```
gzip file (each row = 25 bytes):
  Block 0: header(10B) + extra_len(2B) + extra_prefix(13B)
  Block 1: [MATRIX BLOCK X — 25 bytes — inside FEXTRA]
  Block 2: extra_suffix + start of DEFLATE stream
  Block 3+: compressed data + CRC32 + isize

  gzip.decompress() → sees only DEFLATE payload → target_message ✓
  hash(file)        → sees all blocks including Block 1 → target_hash ✓
```

FEXTRA is used legitimately in bgzip (block gzip for genomic data) and has real-world relevance for polyglot file construction. The flag encodes the solution: **F3X7R4 = FEXTRA**.

### 6.3 Frida-Calibrated Constraint Solving (Bedrock Bank)

Bedrock Bank's `mixValues` function had a subtle Dalvik arithmetic difference: `shr-int` is an arithmetic right shift (sign-extending), unlike Java's `>>>`. A Python port using unsigned shift produced wrong results for states with bit 31 set.

Rather than tracing every edge case, I used Frida to call the real function reflectively on a running Android instance:

```javascript
var kv = Java.use('com.bedrockbank.app.KeyValidator');
var m = kv.class.getDeclaredMethod('mixValues',
    [Java.use('int').class, Java.use('int').class, Java.use('int').class]);
m.setAccessible(true);
// One call with known inputs → ground truth output
// Compare against Python port → identify the shift divergence
```

One Frida call replaced what could have been hours of bytecode analysis. When uncertain about JVM semantics, instrument the real runtime.

---

## 7. Challenge Hardening Recommendations

### Binary Exploitation

**Canopysaurus:** `dtc_table[i] = NULL` after `free()` eliminates the UAF entirely. Combined with `dtc_count = 0`, the bug closes. Enabling PIE would additionally require a separate address leak step. Safe-linking (glibc ≥ 2.32) would require leaking the per-heap secret before controlling tcache forward pointers.

**Jurassic Stack Park:** Removing the PID from the banner immediately breaks the cookie prediction. Seeding from `/dev/urandom` instead of `srand(getpid())` makes it unpredictable. Enabling NX (`-z execstack` removed) forces ROP instead of shellcode. `-fstack-protector-strong` places a genuine compiler canary with kernel-PRNG seeding.

### Cryptography

**Dino Vault:** Both `p` and `q` must be freshly generated per session. If object persistence is required for gameplay, encrypt `vault_key` with a server secret rather than storing a raw prime.

**ZIPPER:** Replacing matrix multiplication with a sponge construction (e.g., Keccak-based) introduces the non-linearity needed to defeat second-preimage attacks. Alternatively, committing to the hash before revealing it in errors removes the oracle.

**Punky Hash:** Increasing coefficient size to ≥ 128 bits raises the difficulty above LLL's practical reach. Introducing a non-linear step (modular squaring, S-box) between rounds further hardens the construction.

### Web

**DinOData:** Apply ownership filters via EF Core global query filters (`HasQueryFilter` on the Note entity), not at the controller layer. Explicitly block cross-entity navigation in the Scientist endpoint's OData query validator. Authorization tests should cover all OData operators, not just direct access.

**Grafasaurus:** Enforce credential rotation at provisioning. Connect Grafana datasources as restricted read-only roles — `COPY FROM PROGRAM` requires `SUPERUSER` or `pg_execute_server_program`. The `readOnly: true` Grafana flag should be enforced at query execution, not just declared in config.

### Reverse Engineering

**Bedrock Bank:** The anti-bypass `deriveFlag` weighted sum gate is worth adopting as a standard pattern for RE challenges. It converts "bypass validateFull" from a viable shortcut into a dead end, forcing real engagement with the problem. If analytical inversion of `mixValues` is intended as the solution path, blocking Frida instrumentation or making the output unobservable without solving the problem would close the calibration shortcut.

---

## 8. Cross-Challenge Design Observations

**Thematic coherence.** The dinosaur theme was not merely cosmetic — it created consistent internal naming (`DinoRandom`, `vault_key`, `Vexillum Rex`, DCU Reset Code) that reduced cognitive overhead and made each challenge feel grounded in a shared world.

**Deliberate difficulty layering.** Red herrings were calibrated to challenge difficulty. Easier challenges had shallower misdirection. Harder challenges layered multiple misdirections requiring understanding the full system before identifying the correct path. This calibration prevents a single technique from short-circuiting.

**Protocol realism.** Canopysaurus is the standout: using a real-world industrial protocol (UDS/CAN) as the exploit delivery mechanism tests protocol knowledge alongside exploitation skill. Challenges that mirror real environments — automotive, embedded, industrial control — are more valuable for professional development than purely artificial constructs.

**The enforcement verification habit.** Across the challenge set, the most transferable lesson is: when a system presents a complex-looking control, verify whether it is actually enforced on the critical path. SecurityAccess in Canopysaurus, the stack cookie in Jurassic Stack Park, the custom PRNG in DinoConfigurator, and the `readOnly` flag in Grafasaurus all appeared meaningful. None of them were, in the context of the actual exploit chain. The discipline of verifying enforcement rather than assuming it is the most valuable habit a security practitioner can develop.

---

*Gjin Krasniqi — gjinikr.github.io — SHC2026 Qualifier — May 2026*

---

## Research Paper

<div style="margin-top:2rem; border:1px solid #1a1a28; border-left:3px solid #00ff88; background:#0c0c14; border-radius:3px; padding:2rem 2.2rem;">
  <div style="font-size:0.6rem; text-transform:uppercase; letter-spacing:3px; color:#00ff88; margin-bottom:1rem;">> research_paper.docx</div>
  <p style="color:#ccccd8; font-size:0.85rem; margin-bottom:1.5rem;">
    The full research paper is available for download. It includes extended analysis, diagrams, and detailed methodology notes not covered in this post.
  </p>
  <a href="/assets/shc2026-research-paper.docx" download
     style="display:inline-flex; align-items:center; gap:0.6rem; background:#00ff88; color:#06060a; font-family:inherit; font-size:0.75rem; font-weight:700; text-transform:uppercase; letter-spacing:2px; padding:0.7rem 1.4rem; border-radius:2px; text-decoration:none; transition:0.2s;">
    &#8595; Download Paper (.docx)
  </a>
  <div style="margin-top:1rem; font-size:0.65rem; color:#40405a; letter-spacing:1px;">
    SHC2026 Qualifier &mdash; Cross-Challenge Structural Analysis &mdash; Gjin Krasniqi
  </div>
</div>
