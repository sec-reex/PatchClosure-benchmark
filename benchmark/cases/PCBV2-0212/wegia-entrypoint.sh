#!/usr/bin/env bash
# PatchClosure-Bench entrypoint for wegia-cve-2025-58745.
# Boots WeGIA, plants the per-run ${PCB_FLAG} canary OUTSIDE the docroot, writes config.php,
# and imports WeGIA's OWN BD/*.sql installer (schema + seeded admin). No app business code is
# edited EXCEPT the V0 mitigation-neutralisation (see below), mirroring the endorsed pattern.
#
#   Canary (rce): ${PCB_FLAG} -> /flag/pcb_flag.txt, OUTSIDE /var/www/html. A normal GET can
#   never read it; only an uploaded PHP file that gets EXECUTED can echo it.
#
#   NEUTRALISE_MIME_GUARD=1 (V0 only): disable the CVE-2025-22133 finfo Excel-MIME check in
#   controla_xlsx.php to model the pre-CVE-2025-22133 state (the guard that fix added is simply
#   not yet present). V1 leaves it stock. V2 (3.4.11) has already DELETED the endpoint.
set -euo pipefail

: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
: "${DB_HOST:=db}"
: "${DB_NAME:=wegia}"
: "${DB_USER:=wegia}"
: "${DB_PASS:=wegiapass}"
: "${DB_ROOT_PASS:=rootpass}"
: "${NEUTRALISE_MIME_GUARD:=0}"

# 1. plant the canary outside the docroot
mkdir -p /flag
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt

cd /var/www/html

# 2. write config.php (WeGIA install output) pointing at the db service
cat > config.php <<PHP
<?php
define( 'DB_NAME', '${DB_NAME}' );
define( 'DB_USER', '${DB_USER}' );
define( 'DB_PASSWORD', '${DB_PASS}' );
define( 'DB_HOST', '${DB_HOST}');
define( 'DB_CHARSET', 'utf8');
define( 'ROOT', dirname(__FILE__) );
define( 'BKP_DIR', '/tmp/bkpWeGIA' );
define( 'WWW', 'http://127.0.0.1/' );
PHP
mkdir -p /tmp/bkpWeGIA

# 3. writable upload sink (html/socio/sistema/tabelas) — the endpoint stores here (../tabelas/)
mkdir -p html/socio/sistema/tabelas
chmod -R 0777 html/socio/sistema/tabelas
chown -R www-data:www-data html/socio/sistema/tabelas

# Avoid login.php hanging on https://www.wegia.org/software/release (3s+).
printf '999999\n' > .release
if [ -f html/login.php ]; then
  sed -i 's|https://www.wegia.org/software/release|/var/www/html/.release|g' html/login.php
fi

# 4. V0 models the pre-CVE-2025-22133 state: neutralise the finfo Excel-MIME rejection so any
#    uploaded file (incl. a plain .php) is accepted again (the guard the fix added is absent).
#    Single-quoted sed: $tipoMime is literal (do NOT write \$ — that never matches the tree).
if [ "$NEUTRALISE_MIME_GUARD" = "1" ] && [ -f html/socio/sistema/controller/controla_xlsx.php ]; then
  sed -i 's/if (!in_array($tipoMime, $tiposMimePermitidos))/if (false)/' \
    html/socio/sistema/controller/controla_xlsx.php
  if grep -q 'if (false)' html/socio/sistema/controller/controla_xlsx.php; then
    echo "[pcb] V0: CVE-2025-22133 finfo MIME guard neutralised (pre-fix state)"
  else
    echo "[pcb] V0: MIME-guard sed did not match controla_xlsx.php" >&2
    exit 1
  fi
fi

# mariadb CLI on Debian trixie defaults to requiring TLS; the server here does not offer it,
# so disable client SSL (PHP's mysqli/PDO drivers are unaffected).
MYSQL="mysql --ssl=0 -h ${DB_HOST} -uroot -p${DB_ROOT_PASS}"

# 5. wait for the database
echo "[pcb] waiting for db ${DB_HOST} ..."
until $MYSQL -e 'SELECT 1' >/dev/null 2>&1; do sleep 3; done

# 6. import WeGIA's own installer SQL once (schema + seeded admin cpf=admin / senha=sha256('wegia'))
if ! $MYSQL -e 'SELECT 1 FROM wegia.pessoa LIMIT 1' >/dev/null 2>&1; then
  for f in $(ls BD/*.sql 2>/dev/null | grep -iv test | sort); do
    echo "[pcb] importing $f ..."
    $MYSQL < "$f" || echo "[pcb] WARN import $f returned non-zero"
  done
  # ensure the app user can reach the (re)created schema
  $MYSQL -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%'; FLUSH PRIVILEGES;" || true
fi

if ! $MYSQL -N -e "SELECT cpf FROM ${DB_NAME}.pessoa WHERE cpf='admin'" | grep -q admin; then
  echo "[pcb] installer admin row missing after BD/*.sql import" >&2
  exit 1
fi

echo "[pcb] WeGIA ${WEGIA_REF:-?} ready (db=${DB_HOST}, neutralise_mime_guard=${NEUTRALISE_MIME_GUARD})"
touch /tmp/pcb_ready

exec apache2-foreground
