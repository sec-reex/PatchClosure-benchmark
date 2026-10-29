#!/usr/bin/env bash
# REAL Admidio boot for the SSO-metadata SSRF pair.
#   1. write adm_my_files/config.php from env (DB reached by STATIC IP -> no DNS for the DB,
#      so the rebinding sidecar's A-query counter is reserved for pcb.test CHECK/FETCH parity),
#   2. wait for MySQL,
#   3. repoint /etc/resolv.conf at the rebinding DNS sidecar so Admidio's OWN gethostbyname()
#      CHECK and libcurl FETCH resolve pcb.test names through it,
#   4. serve real Apache+PHP on :8080. The REAL `install` (create org + admin + DB schema) is
#      driven over EXTERNAL HTTP by oracle.py against Admidio's own install wizard.
set -e

DOCROOT=/opt/app-root/src
CONFIG="${DOCROOT}/adm_my_files/config.php"

echo "[pcb] Admidio profile=${HARNESS_VER:-?} version=$(cat /opt/app-root/.admidio_version 2>/dev/null) DB=${ADMIDIO_DB_HOST}:${ADMIDIO_DB_PORT}"

cat > "${CONFIG}" <<PHP
<?php
\$gDbType = 'mysql';
\$g_tbl_praefix = 'adm';
\$g_adm_srv  = '${ADMIDIO_DB_HOST}';
\$g_adm_port = ${ADMIDIO_DB_PORT};
\$g_adm_db   = '${ADMIDIO_DB_NAME}';
\$g_adm_usr  = '${ADMIDIO_DB_USER}';
\$g_adm_pw   = '${ADMIDIO_DB_PASSWORD}';
\$g_root_path = '${ADMIDIO_ROOT_PATH}';
\$gTimezone = 'UTC';
\$gLoginForUpdate = 0;
\$gPasswordHashAlgorithm = 'BCRYPT';
PHP
chown www-data:www-data "${CONFIG}"
chmod 640 "${CONFIG}"
echo "[pcb] wrote config.php (root_path=${ADMIDIO_ROOT_PATH})"

echo "[pcb] waiting for MySQL at ${ADMIDIO_DB_HOST}:${ADMIDIO_DB_PORT} ..."
until php -r 'try{new PDO("mysql:host=".getenv("ADMIDIO_DB_HOST").";port=".getenv("ADMIDIO_DB_PORT").";dbname=".getenv("ADMIDIO_DB_NAME"),getenv("ADMIDIO_DB_USER"),getenv("ADMIDIO_DB_PASSWORD"));exit(0);}catch(\Throwable $e){exit(1);}' 2>/dev/null; do
  sleep 3
done
echo "[pcb] MySQL is up."

# Route pcb.test resolution through the rebinding sidecar. The DB is reached by a STATIC IP
# (ADMIDIO_DB_HOST) so it never queries this resolver -> the sidecar's per-client A-query
# counter sees ONLY the guard's gethostbyname CHECK then libcurl's FETCH (exact TOCTOU parity).
echo "nameserver ${DNS_SIDECAR_IP:-10.99.0.53}" > /etc/resolv.conf
echo "options ndots:0 timeout:2 attempts:1" >> /etc/resolv.conf
echo "[pcb] resolv.conf -> ${DNS_SIDECAR_IP:-10.99.0.53}"

mkdir -p /var/run/apache2
echo "[pcb] serving real Admidio on 0.0.0.0:8080 (SSRF sink: /modules/sso/fetch_metadata.php)"
exec apache2ctl -D FOREGROUND
