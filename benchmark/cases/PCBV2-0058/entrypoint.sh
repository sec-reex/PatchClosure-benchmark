#!/bin/bash
# Create a Frappe site whose MariaDB schema name embeds PCB_FLAG, then serve
# the real gunicorn app. sites/ is a VOLUME on the official image — do not
# rely on image-layer files under sites/.
set -euo pipefail

BENCH_DIR=/home/frappe/frappe-bench
cd "$BENCH_DIR"

mkdir -p sites
printf 'frappe\n' > sites/apps.txt

bench set-config -g redis_cache "redis://${REDIS_HOST:-redis}:6379/0"
bench set-config -g redis_queue "redis://${REDIS_HOST:-redis}:6379/1"
bench set-config -g redis_socketio "redis://${REDIS_HOST:-redis}:6379/2"
bench set-config -g db_host "${DB_HOST:-db}"
bench set-config -g db_port 3306

echo "[entrypoint] waiting for MariaDB at ${DB_HOST:-db} ..."
for i in $(seq 1 120); do
    if mariadb -h "${DB_HOST:-db}" -u root -p"${DB_ROOT_PASSWORD:-pcbroot}" \
               -e "SELECT 1" >/dev/null 2>&1; then
        echo "[entrypoint] MariaDB ready."
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "[entrypoint] ERROR: MariaDB never came up." >&2
        exit 1
    fi
    sleep 2
done

SITE="${SITE_NAME:-site.local}"
DB="${DB_NAME:-${PCB_FLAG:-testdb}}"

if [ ! -d "sites/${SITE}" ]; then
    echo "[entrypoint] creating site ${SITE}  db=${DB} ..."
    bench new-site "$SITE" \
        --mariadb-root-password "${DB_ROOT_PASSWORD:-pcbroot}" \
        --admin-password admin \
        --db-name "$DB" \
        --mariadb-user-host-login-scope=% \
        --verbose
fi

bench use "$SITE" || true
echo "$SITE" > "$BENCH_DIR/sites/currentsite.txt"
bench --site "$SITE" set-config developer_mode 1

echo "[entrypoint] starting gunicorn on 0.0.0.0:8000 ..."
cd "$BENCH_DIR/sites"
exec "$BENCH_DIR/env/bin/gunicorn" \
    --bind 0.0.0.0:8000 \
    --timeout 120 \
    --workers 1 \
    --graceful-timeout 5 \
    frappe.app:application \
    --preload
