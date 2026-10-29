#!/usr/bin/env bash
# PatchClosure-Bench entrypoint for qdpm-cve-2020-7246.
# Boots qdPM, plants the per-run ${PCB_FLAG} canary OUTSIDE the docroot, then drives
# qdPM's OWN HTTP installer (writes databases.yml + schema + configuration) and seeds one
# ordinary member account for the differential. No app business code is edited.
#
#   Canary (rce): ${PCB_FLAG} -> /flag/pcb_flag.txt, OUTSIDE /var/www/html. A normal GET can
#   never read it; only an uploaded PHP file that gets EXECUTED can echo it.
#
#   STRIP_UPLOAD_HTACCESS=1 (V0 only): neutralise uploads/.htaccess script-block to model the
#   pre-CVE-2015-3884 state (the mitigation that fix relies on is simply not yet present).
set -euo pipefail

: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
: "${DB_HOST:=db}"
: "${DB_NAME:=qdpm}"
: "${DB_USER:=qdpm}"
: "${DB_PASS:=qdpmpass}"
: "${STRIP_UPLOAD_HTACCESS:=0}"

# 1. plant the canary outside the docroot
mkdir -p /flag
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt

cd /var/www/html

# 2. writable runtime dirs (symfony cache/log + upload sinks)
mkdir -p core/cache core/log uploads/users uploads/attachments
chmod -R 0777 core/cache core/log uploads core/config
chown -R www-data:www-data core/cache core/log uploads core/config

# 3. V0 models the un-mitigated CVE-2015-3884 condition: neutralise EVERY script-block
#    .htaccess under uploads/ (qdPM ships one in uploads/ AND one in uploads/users/, and
#    Apache applies them cumulatively to the subtree).
if [ "$STRIP_UPLOAD_HTACCESS" = "1" ]; then
  find uploads -name .htaccess -type f -exec sh -c ': > "$1"' _ {} \;
  echo "[pcb] V0: uploads/**/.htaccess script-blocks neutralised (pre-CVE-2015-3884 state)"
fi

# 4. fresh install marker each boot
rm -f core/config/databases.yml

# 5. wait for the database
echo "[pcb] waiting for db ${DB_HOST} ..."
until mysql -h "$DB_HOST" -u"$DB_USER" -p"$DB_PASS" -e 'SELECT 1' "$DB_NAME" >/dev/null 2>&1; do
  sleep 3
done

# 6. start apache in the background so qdPM's own installer can run over HTTP
apache2-foreground &
APACHE_PID=$!

echo "[pcb] waiting for apache ..."
until curl -fsS "http://127.0.0.1/install/index.php" >/dev/null 2>&1; do sleep 2; done

# 7. run qdPM's real installer (loads install.sql, seeds configuration, writes databases.yml)
if [ ! -f core/config/databases.yml ]; then
  curl -fsS "http://127.0.0.1/install/index.php?action=install_qdpm" \
    --data-urlencode "db_host=${DB_HOST}" \
    --data-urlencode "db_port=" \
    --data-urlencode "db_username=${DB_USER}" \
    --data-urlencode "db_password=${DB_PASS}" \
    --data-urlencode "db_name=${DB_NAME}" \
    --data-urlencode "administrator_email=admin@pcb.local" \
    --data-urlencode "administrator_password=adminpass" \
    --data-urlencode "app_name=PCB" \
    --data-urlencode "app_short_name=PCB" \
    --data-urlencode "email_label=PCB" >/dev/null 2>&1 || true
fi

# 8. seed one ordinary member (login accepts a 32-char md5 password hash)
mysql -h "$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" >/dev/null 2>&1 <<SQL || true
INSERT INTO users (users_group_id,name,photo,email,culture,password,active)
SELECT 1,'poc',NULL,'poc@pcb.local','en',MD5('pocpass'),1
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email='poc@pcb.local');
SQL

chown -R www-data:www-data uploads core/cache core/log
echo "[pcb] qdPM ${QDPM_VER:-?} ready (db=${DB_HOST}, strip_htaccess=${STRIP_UPLOAD_HTACCESS})"

wait "$APACHE_PID"
