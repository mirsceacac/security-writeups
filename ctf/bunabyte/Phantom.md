# Phantom JPEG

| Field | Value |
|---|---|
| Author | mirsceacac |
| Platform | CTF (offline pcap handout) |
| Category & Difficulty | Network Forensics, Easy–Medium |
| Status | CTF challenge |
| Date | 2026-10-29 |
| Skills exercised | `tshark` field extraction, ICMP covert-channel analysis, hex decoding, JPEG structure (SOI/APP0/COM/DQT), shell discipline |

## TL;DR
A suspicious ICMP stream carried a JPEG across many ping payloads. A single anomalous packet (TTL 1, corrupt checksum, payload `check_me_out`) marked the start of the real data. Real chunks were prefixed with the literal string `start_of_jpeg` and separated by `filler data` decoys. Concatenating the three chunks and hex-decoding produced a valid JFIF file whose COM segment contained the flag.

**Flag:** `bb{icmp_carved_jpeg_forensics}`

---

## Reconnaissance & Enumeration

**What I ran → what I saw → what it suggested.**

```bash
unzip phantom_jpeg.zip && ls
```
→ `phantom_jpeg.pcap` (single artifact). Suggested: pure offline forensics, no live host.

```bash
tshark -r phantom_jpeg.pcap -Y "icmp" -T fields -e ip.ttl -e icmp.type | sort | uniq -c
```
→ Almost all packets at TTL 64/128, **one** packet at TTL 1. The briefing called this out — confirmed the marker exists and lives inside the ICMP stream, not UDP/TCP.

```bash
tshark -r phantom_jpeg.pcap -Y "ip.ttl == 1" -T fields -e ip.ttl -e icmp.checksum -e data.data
```
→ One echo packet, TTL 1, bad checksum, payload hex-decoding to `check_me_out`. Suggested: everything meaningful starts *after* this packet.

```bash
tshark -r phantom_jpeg.pcap -Y "icmp" -T fields -e data.data > icmp_payloads.txt
head icmp_payloads.txt
```
→ First thousands of lines are `ping request N` / `ping reply N` — the "normal pings" the NIDS story mentions. Dead end by design; moved on.

```bash
grep -vE '^70696e67' icmp_payloads.txt | head -30
```
→ Stream breaks into: `check_me_out`, then 20× `filler data`, then a chunk starting `start_of_jpeg…`, repeat. Suggested: delimiter-based chunking, no exotic encoding required.

*(No web/host enumeration — this is a pcap-only challenge. No vhosts, no `nmap`. The "recon" here is protocol and byte-pattern recon.)*

---

## Vulnerability Analysis

- **Identified:** **ICMP covert channel** (MITRE ATT&CK T1048 / T1071.001-adjacent) plus **JPEG metadata abuse**. Exfiltration rides inside ICMP `data.data`; the flag is embedded as a **COM (`FFFE`) segment**, not in pixel data.
- **Confirmed manually:** the hex dump shows plaintext ASCII markers (`check_me_out`, `filler data`, `start_of_jpeg`) mixed into ping payloads. The real chunks begin with a fixed delimiter (`73746172745f6f665f6a706567`) followed by `FFD8 FFE0 …` — unmistakable JFIF bytes. No need to trust any tool's "verdict"; the bytes speak for themselves.
- **Impact (in-story):** data exfiltration across a channel that most networks permit by default; in-challenge impact is flag recovery.
- **Preconditions:** attacker needs raw ICMP outbound and must be able to encode chunks (any framing works — delimiter, sequence number, TTL, etc.). The author chose the simplest framing: literal delimiter + decoy padding.

**Key file signature table used during analysis:**

| Bytes | Meaning |
|---|---|
| `FF D8` | JPEG SOI (start of image) |
| `FF E0 00 10 4A 46 49 46 00 …` | APP0 / JFIF |
| **`FF FE`** | **COM (comment) segment** — the flag lives here |
| `FF DB` | DQT (quantization table) |
| `FF D9` | EOI (end of image) |

---

## Exploitation & Post-Exploitation

1. **Confirm marker semantics.** Locate TTL-1 / bad-checksum packet; decode its payload (`check_me_out`). Decision: treat it as the boundary — everything before is noise.
2. **Extract every ICMP payload as hex.** `tshark -T fields -e data.data` (see above). One packet per line keeps ordering trivial.
3. **Identify the framing.** Lines matching `^73746172745f6f665f6a706567` are real chunks; `filler data` lines are decoys. Decision: filter by prefix, not by "any non-ping payload" — decoys would otherwise pollute the stream.
4. **Strip the delimiter and hex-decode.** Keep bytes after the prefix; concatenate in file order (which equals capture order, which equals author's intended order).
5. **Write and inspect the artifact.**
   ```bash
   file phantom.jpg
   # phantom.jpg: JPEG image data, JFIF standard 1.01, ...
   ```
6. **Read the flag from the COM segment** — no image viewer required:
   ```bash
   strings phantom.jpg
   # ... bb{icmp_carved_jpeg_forensics}
   ```
7. **Confirm the off-by-one "phantom" detail.** The COM length field `0x20` (32) includes its own 2 bytes, so a strict decoder expects 30 bytes of payload — but the flag is 31. This is the intended "corrupt/commented" quirk; a lenient carver (or `strings`) ignores it.

**Working script — `scripts/solve.py`:**

```python
import binascii, re

PREFIX = "73746172745f6f665f6a706567"  # "start_of_jpeg"
chunks = []
with open("icmp_payloads.txt") as f:
    for line in f:
        line = line.strip()
        if line.startswith(PREFIX):
            chunks.append(line[len(PREFIX):])

data = b"".join(binascii.unhexlify(c) for c in chunks)
open("phantom.jpg", "wb").write(data)

print(f"[+] Chunks: {len(chunks)}  Size: {len(data)} B  Header: {data[:4].hex()}")
print("[+] Flag:", re.search(rb"bb\{[^}]+\}", data).group().decode())
```

**Proof output:**

```text
[+] Found 3 JPEG chunks
[+] Wrote phantom.jpg (430 bytes)
[+] Header: ffd8ffe0
[+] Flag: bb{icmp_carved_jpeg_forensics}
```

**Mistakes made along the way (kept for honesty):**

- Pasting Python into zsh → `zsh: parse error near ')'`. Fix: heredoc into `solve.py`, then `python3 solve.py`.
- First `grep` on the hex file assumed a one-prefix scheme; needed `^7374617274…` to skip `filler data`. Fix: anchor on the actual delimiter, not on "any non-`ping` line".

Links to scripts: `scripts/solve.py`.

---

## Flag

```text
bb{icmp_carved_jpeg_forensics}
```

Location: JPEG **COM segment** (`FFFE`), length `0x20`, inside `phantom.jpg` rebuilt from three ICMP chunks.

---

## Lessons Learned

- **Pattern:** *Literal ASCII markers inside binary streams are your best friend in forensics CTFs.* A hex dump that suddenly reads `check_me_out` / `start_of_jpeg` / `filler data` means the framing is deliberately human-readable — stop looking for exotic encodings and start filtering by prefix.
- **Method:** *Treat a "corrupt" packet as a signal, not an error.* TTL 1 + bad checksum is the author telling you "start here." Same logic applies to malformed JPEG COM lengths — the anomaly is the challenge, not a bug to bypass.
- **Method:** *JPEG metadata is fair game.* Before opening an image, run `strings` and `binwalk` on it — `COM`, `APPn`, and `EXIF` segments routinely hold flags, credentials, and C2 URLs in real incidents too.
- **Tooling:** *Save every intermediate.* `icmp_payloads.txt`, `phantom.jpg`, and the solve script were kept on disk; every later question ("how many chunks?", "what's the COM length?") was answered by `grep`/`xxd` rather than re-running `tshark`. Cheap and repeatable.
- **Shell:** Python goes in a file, not a prompt. A heredoc (`<<'EOF' … EOF`) is the reliable way to create one from a terminal.

---

## Mitigation & Detection

**Fix / prevent (defender view):**

- **Restrict ICMP egress** at the perimeter: allow echo request/reply to known destinations only; block ping payloads above a size threshold from reaching untrusted hosts.
- **Deep-inspect ICMP payloads** at egress; flag packets carrying magic-byte signatures (`FF D8`, `PK\x03\x04`, `%PDF`) or long ASCII runs in `data.data`.
- **Content disarm / sanitize images** at ingress so `COM`/`APPn` metadata is stripped before the file reaches users (also kills a real exfil vector).
- **Strip/ignore COM segments** in any pipeline that ingests untrusted images — no legitimate workflow needs attacker-controlled comments.

**Detect (query sketches):**

- **ICMP anomaly:** alert when a single source emits ICMP packets with `ip.ttl == 1` *and* `icmp.checksum` fails verification — extremely rare from real hosts, almost always a tool or a CTF-style beacon.
- **Volume:** baseline ICMP per-host; alert on >N packets/min or total payload volume above median by a wide margin, especially to a single destination.
- **Content:** alert on any ICMP packet whose `data.data` starts with a magic number (`ffd8ff`, `504b0304`, `25504446`, `7f454c46`) — a decisive covert-channel indicator.
- **File-egress:** on file gateways, log and quarantine JPEGs whose `COM` segment length disagrees with actual payload length (the "phantom" signature in this challenge) or whose `COM`/`APPn` contain printable ASCII runs longer than ~16 bytes.
