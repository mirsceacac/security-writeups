# The Vault Door

| Field | Value |
|---|---|
| Author | mirsceacac |
| Platform | Bunabyte CTF lab |
| Category & Difficulty | Cryptography, 400 pts (0 solves at time of writing) |
| Status | Live |
| Date | 2026-10-30 |
| Skills exercised | AES-CBC internals, PKCS#7 padding oracle, async HTTP fuzzing |

## TL;DR
A captured session token was AES-CBC encrypted (16-byte IV + 6 ciphertext blocks) using a server-side key we never had. The decrypt endpoint leaked PKCS#7 padding validity, so a classic padding-oracle attack recovered all six plaintext blocks. The token contained a JSON session with the flag in the `token` field: `BB{p4dd1ng_0r4cl3_vau1t_br34ch}`.

## Reconnaissance & Enumeration

**Files provided**
- `intercepted_token.bin` — 112 bytes → `IV (16) || CT (96)` = 6 ciphertext blocks.
- `server_snippet.py` — redacted excerpt showing `AES.new(SECRET_KEY, AES.MODE_CBC, iv)` and `unpad(cipher.decrypt(ct), 16)` inside `try/except`. That's the classic shape of a padding oracle: decryption succeeds → "OK"; `unpad` throws → error response.

**Endpoint description from the challenge**
`GET /oracle?ct=<hex IV||CT>` returns `VALID_PADDING`, `INVALID_PADDING`, or `INVALID_INPUT`. Body-only signal, always HTTP 200 — so the oracle must be classified on the response body, not the status code.

**Baseline checks**

```
xxd -g1 intercepted_token.bin
00000000: 01 0d 48 f4 b8 5a b3 7d fa c5 a6 a3 04 cc ae 22  ..H..Z.}......."
00000010: 65 67 f4 d1 3d 55 32 5a 03 bf 79 a8 aa b4 29 31  eg..=U2Z..y...)1
...
```

```
time curl -s "$BASE?ct=$TOKEN"
VALID_PADDING
real 0.47s     # ~2 req/s per connection → need concurrency
```

A first sanity check I ran — flipping **the first byte of the IV** — still returned `VALID_PADDING`. That's expected, not a server bug: modifying `IV[0]` only corrupts the *first* plaintext block; the padding lives in the *last* block, so it stays valid. Lesson: to break padding you must corrupt the last ciphertext block, or the `prev` block of whichever block you're targeting.

**Dead end avoided:** an initial single-threaded `urllib` script looked "frozen" because 6 blocks × 16 bytes × 256 guesses ≈ 24k sequential HTTPS calls at ~2 req/s is ~3.5 hours. Concurrency was mandatory, not optional.

## Vulnerability Analysis

- **Identified:** CWE-209 / padding oracle on AES-CBC (essentially POODLE/Lucky13 family). The server distinguishes `VALID_PADDING` from `INVALID_PADDING` — a one-bit side-channel on the decryption outcome.
- **Confirmed manually:** `curl "$BASE?ct=<original 112-byte token>"` → `VALID_PADDING`. Corrupting the last ciphertext block → `INVALID_PADDING`.
- **Impact:** Any attacker who sees a ciphertext transmitted over the wire (as the audit "captured" one) can decrypt the whole thing without the key, by submitting chosen `(prev, block)` pairs and reading the padding verdict.

Padding oracle in one paragraph: to recover byte `i` of plaintext block `C_i`, XOR the previous block `C_{i-1}` with guessed bytes so the decrypted last byte equals the desired padding value `pad`. When the oracle says `VALID_PADDING`, you've solved `D(C_i)[j] = guess ^ pad`, and then `P_i[j] = D(C_i)[j] ^ C_{i-1}[j]`. Repeat 16× per block.

## Exploitation

1. **Parsed the token.** Split `intercepted_token.bin` into `iv = data[:16]`, `ct = data[16:]`, chopped into 6 blocks of 16. Target: recover all 6 plaintext blocks.

2. **Wrote an async oracle client.** `aiohttp` with a semaphore (`CONC=20`) gave ~40 req/s aggregate, so a full 6-block decrypt finished in ~3–5 min instead of hours.

3. **Handled the pad=1 false positive.** This is the subtle part that bit the first attempt. When the true padding is `0x02 0x02`, then *any* guess `g` that makes the last byte `0x02` returns `VALID_PADDING`, so the naive "first valid byte wins" rule assigns a **wrong** intermediate byte at pad=1, and pad=2 then has no solution → `RuntimeError: pad=2: no byte found`.
   Fix: at `pad == 1` only, confirm by additionally flipping `byte[BS-2]` (the byte that would become the 2nd padding byte if pad were 2); if that still returns `VALID_PADDING`, it's a real 1-byte pad. For `pad > 1`, once `inter[15]` is pinned there are no false positives, so a plain "first valid" rule is safe.

4. **Decrypted block by block** using `C_{i-1}` (or `IV`) as the previous block, then XOR'd `D(C_i) ^ C_{i-1}`.

5. **Stripped PKCS#7** and pattern-matched `flag\{...\}`.

Recovered plaintext:

```json
{"user":"analyst_07","role":"auditor","vault":"B","token":"BB{p4dd1ng_0r4cl3_vau1t_br34ch}"}
```

Script: `exploit_fast.py` (asyncio + aiohttp + flip-check for pad=1). Core loop:

```python
for pad in 1..16:
    for guess in 0..255:
        mod = prev[:]
        mod[BS-pad] = guess
        for k in 1..pad-1:
            mod[BS-k] = inter[BS-k] ^ pad       # force already-known tail
        if oracle(mod + block) != VALID_PADDING: continue
        if pad == 1 and oracle(flip(mod, BS-2) + block) != VALID_PADDING:
            continue                            # reject pad=2..16 masquerading as pad=1
        inter[BS-pad] = guess ^ pad
        break
plain = inter[i] ^ prev[i]
```

## Flag
`BB{p4dd1ng_0r4cl3_vau1t_br34ch}` — inside `token` in the recovered JSON.

## Lessons Learned

- **Pattern:** "CBC + unpad-or-throw + distinguishable error" is *always* a padding oracle. When you see `try: unpad(cipher.decrypt(...))` next to a body that reports the exception outcome, don't bother attacking the key — attack the padding.
- **Method:** The pad=1 false-positive is *the* classic off-by-one in padding-oracle scripts. **Always** add the "flip byte `BS-2` too" confirmation at pad=1, even at the cost of one extra request per block. Without it the attack silently produces wrong intermediate bytes and then dies at pad=2 with an unhelpful "no byte found."
- **Sanity-check your sanity-checks.** Flipping `IV[0]` and seeing `VALID_PADDING` initially looked like the oracle was broken; it wasn't, because padding lives in the last block. Before declaring an oracle misbehaving, corrupt the *right* bytes (last ciphertext block, or the block immediately preceding the targeted one).
- **Method:** Sequential HTTP oracles look "hung." If a script produces no output for >30 s against a network oracle, it's rate-limited, not buggy. Wrap every oracle call in `asyncio.gather` with a semaphore before assuming you have a logic bug.

## Mitigation & Detection

**Fix (server side):**
- **Encrypt-then-MAC (AEAD).** Use AES-GCM or AES-CBC + HMAC-SHA256 with the MAC compared in constant time *before* decrypting. Padding errors then become indistinguishable from MAC failures — which the caller should collapse into one generic "invalid token."
- **Uniform error responses.** Return the same status + body for "invalid padding," "bad MAC," and "malformed JSON," and enforce a constant-ish response time (compare after MAC verify, not before).
- **Rate limiting** on the oracle endpoint (e.g. 10 req/min/IP) so even a leaky oracle is not brute-forceable at 40 req/s.
- **Rotate the key** — the ciphertext from this capture is now public, so any 16-byte block of it is recoverable by the same attack.

**Detect:**
- Count `VALID_PADDING` responses per source IP per minute; a single client hitting hundreds/thousands is a padding-oracle search, not a real staff session.
- Alert when a token is submitted with a `ct` length that doesn't match any currently issued token, or when the same token's `ct` prefix repeats with a changing last byte across many requests.
- Log-tag every padding-failure branch with a "security" severity; a burst of `INVALID_PADDING` from one IP is essentially an IDS signature.
