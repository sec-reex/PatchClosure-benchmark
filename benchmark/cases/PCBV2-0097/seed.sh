#!/bin/bash
# Install the REAL Concrete CMS against real MySQL, then create a REAL Express object + a REAL
# express_entry_list block on the home page (so the render path's unserialize() sink is reachable),
# and expose the REAL-app HTTP driver in the webroot. All via the real Concrete CMS bootstrap/APIs.
set -u
cd /app
DBHOST="${DB_HOST:-db-v1}"
MARK=/app/application/config/database.php

log(){ echo "PCB_SEED: $*"; }

# --- wait for DB ------------------------------------------------------------------------------
for i in $(seq 1 60); do
  if mysql --skip-ssl -h "$DBHOST" -uconcrete -pconcrete -e 'select 1' concrete >/dev/null 2>&1; then break; fi
  sleep 2
done

# --- install (idempotent) ---------------------------------------------------------------------
if [ ! -f "$MARK" ]; then
  log "installing Concrete CMS ..."
  C5_CLI_ALLOW_AS_ROOT=1 php -d memory_limit=-1 concrete/bin/concrete c5:install \
      --allow-as-root \
      --db-server="$DBHOST" --db-username=concrete --db-password=concrete --db-database=concrete \
      --admin-password='Passw0rd!' --site='PCB' --starting-point=atomik_blank \
      --ignore-warnings -n 2>&1 | tail -25
  log "install exit=$?"
else
  log "already installed"
fi

# --- fix permissions so apache (www-data) can write to cache/config ---------------------------
chown -R www-data:www-data /app/application/files /app/application/config 2>/dev/null || true
chmod -R 775 /app/application/files /app/application/config 2>/dev/null || true

# --- create Express object + block + copy driver ----------------------------------------------
cp /work/pcb_driver.php /app/pcb_driver.php
log "seeding Express object + block ..."
php -d memory_limit=-1 /work/pcb_seed.php 2>&1 | tail -40
log "seed done; bID=$(cat /app/application/files/pcb_bid.txt 2>/dev/null)"
