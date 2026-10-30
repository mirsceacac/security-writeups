# treasure (buna-byte)

| Field | Value |
|---|---|
| Author | mirsceacac |
| Platform | buna-byte CTF |
| Category & Difficulty | Reverse Engineering, Easy–Medium |
| Status | Live |
| Date | 2026-10-29 |
| Skills exercised | ELF triage, `strings` analysis, PyInstaller unpacking, Python bytecode disassembly (`dis`/`marshal`), base64 decoding, spotting decoy logic |

## TL;DR
`treasure` is a stripped 64-bit ELF that, when run, prints only `The secret treasure is hidden in: **********`. It is actually a **PyInstaller-packed Python 3.13 executable**, not a native binary. Unpacking the archive with `pyinstxtractor-ng` yields `treasure.pyc`, whose bytecode contains a hardcoded base64 blob. Decoding that blob gives the flag `bb{easy_r3v_challenge_s0lv3d}`. The XOR loop in `decode_message()` is a decoy — its output is unprintable garbage and is never printed by `main()` anyway.

## Reconnaissance & Enumeration

- **Run it once to establish the decoy behavior.**
  ```bash
  chmod +x treasure && ./treasure
  ```
  → `The secret treasure is hidden in: **********`.
  Ten literal asterisks, no input prompt, no further output. Combined with the challenge blurb ("Don't believe what the program tells you at first glance"), this confirmed the printed line is bait.

- **Identify the file.**
  ```bash
  file treasure
  ```
  → `ELF 64-bit LSB executable, x86-64, ... stripped`.
  Stripped → `nm`/`objdump` symbols won't help. Expected for CTF RE.

- **The pivot: readable strings.**
  ```bash
  strings -a treasure | less
  ```
  Filtered hits that changed the plan entirely:
  ```
  Py_DecRef
  Py_DecodeLocale
  PyInitConfig_Create
  _pyi_main_co
  PYZ.pyz
  libpython3.13.so
  pyi-contents-directory _internal
  streasure
  zPYZ.pyz
  ```
  → **PyInstaller-packed Python 3.13 executable.** The real logic is Python bytecode inside the embedded `PYZ.pyz` archive, not the x86 stub. `streasure` = size-byte prefix `s` + entry name `treasure`; `zPYZ.pyz` = zlib-flag `z` + `PYZ.pyz`.

- **Dead ends (recorded briefly):**
  - `objdump -d -M intel treasure` → thousands of instructions around `dlopen`, `fork`, `execvp`, `pyi_*`. This is the PyInstaller bootloader, **not** the program logic. Wasted ~10 minutes.
  - `binwalk treasure` → dozens of "Zlib compressed data" hits, all of them entries inside the PYZ archive. `binwalk` is the wrong tool for PyInstaller; it produces noise here.

## Vulnerability Analysis
- **Identified:** *Credential-free static extraction* of a PyInstaller bundle (CWE-927 / "missing code obfuscation" of the shipped artifact). PyInstaller is designed to be unpacked at runtime; there is no secret in the loader, only in the extracted Python bytecode.
- **Confirmed manually:** `strings treasure` reveals `_pyi_main_co`, `PYZ.pyz`, and `libpython3.13.so` — fingerprints that uniquely identify a PyInstaller 6.x bundle running on CPython 3.13.
- **Impact:** Anyone with read access to the executable can extract the exact source-level bytecode, defeat the "stripped ELF" obfuscation, and read every hardcoded constant. In a real product this means any secret baked into a PyInstaller binary (API keys, decryption keys, license checks) is effectively public.

## Exploitation & Post-Exploitation

1. **Why extract rather than disassemble.** Once `strings` proved the binary was a PyInstaller stub, continuing with x86 disassembly would only reconstruct the bootloader. The shortest path to the logic is the embedded PYZ archive.

2. **Install the extractor (Kali PEP 668 workaround).**
   ```bash
   python3 -m pip install --user pyinstxtractor-ng
   ```
   → `error: externally-managed-environment` (PEP 668). Installed cleanly via `pipx`:
   ```bash
   sudo apt install pipx
   pipx ensurepath
   # reopen terminal
   pipx install pyinstxtractor-ng
   ```
   → `installed package pyinstxtractor-ng 2026.7.3 ... done!`

3. **Unpack the archive.**
   ```bash
   pyinstxtractor-ng treasure
   ```
   Key output:
   ```
   [+] Pyinstaller version: 2.1+
   [+] Python version: 3.13
   [+] Found 30 files in CArchive
   [+] Possible entry point: treasure.pyc     <-- target
   [+] Found 112 files in PYZ archive
   [+] Successfully extracted pyinstaller archive: treasure
   ```
   Result: `treasure_extracted/treasure.pyc` (the original compiled script) plus `PYZ.pyz`, `libpython3.13.so`, `_internal/`, and other runtime files.

4. **Disassemble the bytecode with the interpreter's own `dis`.**
   Python 3.13 is too new for `uncompyle6`/`decompyle3`/`pycdc`; `dis` + `marshal` is exact and version-proof. The header offset in a PyInstaller-extracted `.pyc` varies by version, so the loader tries a small set of common offsets:
   ```bash
   python3.13 - <<'PY'
   import marshal, dis, types, pathlib
   data = pathlib.Path("treasure_extracted/treasure.pyc").read_bytes()
   for off in (16, 12, 8, 0):
       try:
           code = marshal.loads(data[off:])
           if isinstance(code, types.CodeType):
               print(f"[+] offset {off}, name={code.co_name}")
               dis.dis(code)
               break
       except Exception:
           pass
   PY
   ```
   → `[+] offset 16, name=<module>` — the `treasure.py` module.

5. **Read the disassembly.** Reconstructed Python source:
   ```python
   import base64, hashlib

   def decode_message():
       encoded = 'YmJ7ZWFzeV9yM3ZfY2hhbGxlbmdlX3MwbHYzZH0='
       key = hashlib.md5(b's3cr3t_k3y').hexdigest()[:8]
       data = base64.b64decode(encoded).decode('utf-8')
       result = ''
       for i, char in enumerate(data):
           result += chr(ord(char) ^ ord(key[i % len(key)]))
       return result

   def main():
       print("The secret treasure is hidden in: **********")
       hidden = decode_message()     # computed, never printed
   ```
   Two observations from the bytecode:
   - `main()` **stores** `hidden` and then returns without printing it — so even if the XOR were meaningful, the user would never see it.
   - The XOR operates on printable ASCII against hex characters (values 48–57 / 97–102), producing control characters — a deliberate decoy, not a cipher.

6. **Decode the flag.**
   ```bash
   echo 'YmJ7ZWFzeV9yM3ZfY2hhbGxlbmdlX3MwbHYzZH0=' | base64 -d
   ```
   → `bb{easy_r3v_challenge_s0lv3d}`

7. **Verify the decoy (sanity check).** Running the XOR loop as the challenge presents it yields control-character garbage:
   ```
   SfCU9
   U]
     =     ]Q
   ```
   Confirms the XOR is noise, and the intermediate `data` value is the intended answer.

*Scripts referenced:* the disassembly helper above is stored as `scripts/disasm.py`; the flag decoder as `scripts/decode.py`.

## Flag
`bb{easy_r3v_challenge_s0lv3d}` — extracted from the base64 constant in `treasure.pyc` inside the PyInstaller archive.

## Lessons Learned

- **Pattern:** Any "ELF" that prints something simple and contains `Py_*` / `PYZ` / `libpython*.so` strings is a PyInstaller (or Nuitka/Cython) bundle. Stop disassembling x86; go straight for `pyinstxtractor-ng`.
- **Method:** `strings -a` is *the* first tool on a stripped binary. PyInstaller, PyOxidizer, Go, and Rust binaries all leak language markers into `.rodata`; recognizing them shortcuts hours of assembly work.
- **Tooling:** Match the disassembler to the runtime version. `python3.13 -m dis` / `marshal.loads` is more reliable than third-party decompilers for bleeding-edge CPython bytecode, and it needs zero installs (which also dodges PEP 668 issues).
- **Mindset:** Read `main()` critically. If the interesting function's return value is stored and then never used, the author is telling you the printed output is a decoy — the value itself is the flag.

## Mitigation & Detection

- **Fix (for developers shipping Python apps):** treat PyInstaller artifacts as public source. Never bake secrets, license keys, or decryption keys into a PyInstaller build. Fetch them at runtime from an authenticated service, or gate them behind server-side checks. Use Nuitka with `--nofollow-imports` or Cython/CFFI for modules that must contain logic you don't want trivially readable — but never rely on "stripped" as security.
- **Fix (for this challenge):** none needed — the shipped artifact *is* the answer; that's the point.
- **Detect (if this were a production artifact):** in CI, scan release binaries with `pyinstxtractor-ng` / `pyi-archive_viewer` and fail the build if the extracted `.pyc` contains high-entropy string literals matching secret patterns (`AKIA…`, `sk_live_…`, base64 blobs > 32 chars) — this catches the exact class of leak this challenge demonstrates.
