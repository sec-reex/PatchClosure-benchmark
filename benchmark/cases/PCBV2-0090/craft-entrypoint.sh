#!/bin/sh
# REAL Craft CMS boot for the GraphQL Asset-upload SSRF pair.
#   1. wait for MySQL (reached by STATIC IP so NO DNS lookup is needed for the DB;
#      this keeps the rebinding sidecar's A-query counter reserved for pcb.test only),
#   2. run the REAL `php craft install` (non-interactive),
#   3. create an asset filesystem + volume and open the PUBLIC GraphQL schema to the
#      asset-upload mutation (pcb_setup.php, via Craft's own service layer),
#   4. repoint /etc/resolv.conf at the rebinding DNS sidecar so Craft's OWN
#      validateHostname() gethostbyname (CHECK) and Guzzle/libcurl (FETCH) resolve
#      pcb.test names through it,
#   5. serve Craft's real web/index.php (GraphQL endpoint + public asset URLs).
set -eu
cd /app

echo "[pcb] Craft profile HARNESS_VER=${HARNESS_VER:-?}  DB=${CRAFT_DB_SERVER}:${CRAFT_DB_PORT}"

echo "[pcb] waiting for MySQL at ${CRAFT_DB_SERVER}:${CRAFT_DB_PORT} ..."
until php -r 'try{new PDO("mysql:host=".getenv("CRAFT_DB_SERVER").";port=".getenv("CRAFT_DB_PORT").";dbname=".getenv("CRAFT_DB_DATABASE"),getenv("CRAFT_DB_USER"),getenv("CRAFT_DB_PASSWORD"));exit(0);}catch(\Throwable $e){exit(1);}' 2>/dev/null; do
  sleep 3
done
echo "[pcb] MySQL is up."

mkdir -p /app/web/uploads
chmod 777 /app/web/uploads

# Minimal, version-safe general config (the 5.8.0 starter's general.php calls fluent methods
# that don't exist in the pinned 5.8.20/5.8.22/5.8.23 GeneralConfig). @webroot must resolve so
# the Local asset fs path @webroot/uploads writes under the served docroot.
cat > /app/config/general.php <<'PHP'
<?php
use craft\config\GeneralConfig;
return GeneralConfig::create()
    ->aliases(['@webroot' => dirname(__DIR__) . '/web'])
    ->allowAdminChanges(true)
    ->devMode(false)
    ->omitScriptNameInUrls(false);
PHP

if ! php craft install/check >/dev/null 2>&1; then
  echo "[pcb] running real Craft install ..."
  php craft install \
      --username=admin \
      --email=admin@example.com \
      --password='Password123!' \
      --site-name=PCB \
      --site-url="${CRAFT_PUBLIC_URL:-http://localhost}" \
      --language=en-US \
      --interactive=0
else
  echo "[pcb] Craft already installed."
fi

echo "[pcb] configuring asset fs + volume + public GraphQL schema ..."
php /app/pcb_setup.php

# Route pcb.test resolution through the rebinding sidecar. The DB is reached by static
# IP (CRAFT_DB_SERVER) so it never queries this resolver -> the sidecar's per-client
# A-query counter sees ONLY the guard's CHECK then Guzzle's FETCH (exact TOCTOU parity).
echo "nameserver ${DNS_SIDECAR_IP:-192.0.0.53}" > /etc/resolv.conf
echo "options ndots:0 timeout:2 attempts:1" >> /etc/resolv.conf
echo "[pcb] resolv.conf -> ${DNS_SIDECAR_IP:-192.0.0.53}"

# Apache as www-data; Craft writes storage/config/web. Do not exec apache until
# install+pcb_setup finished — otherwise :80 is an empty-vhost 404, not GraphQL.
chown -R www-data:www-data /app/storage /app/web/uploads /app/config /app/web/cpresources 2>/dev/null || true
echo "[pcb] serving real Craft via Apache on 0.0.0.0:80 (GraphQL: /index.php?p=actions/graphql/api)"
exec apache2-foreground
