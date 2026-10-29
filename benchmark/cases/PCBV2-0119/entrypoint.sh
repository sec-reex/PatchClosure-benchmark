#!/bin/bash
# GLPI test-env entrypoint: CLI-install against the mariadb sidecar (no wizard),
# plant the per-run canary, put the seeded admin in DEBUG mode so SQL errors
# reflect into HTTP bodies, then serve the real product.
set -uo pipefail

DB_HOST="${DB_HOST:-db}"
DB_NAME="${DB_NAME:-glpi}"
DB_USER="${DB_USER:-glpi}"
DB_PASS="${DB_PASS:-glpipass}"
: "${PCB_FLAG:?PCB_FLAG must be set to the per-run canary token}"

cd /var/www/html

echo "[entrypoint] waiting for MariaDB at ${DB_HOST}..."
ok=0
for i in $(seq 1 90); do
    if mysqladmin ping -h "$DB_HOST" -u"$DB_USER" -p"$DB_PASS" --silent 2>/dev/null; then
        echo "[entrypoint] DB is up"
        ok=1
        break
    fi
    sleep 2
done
if [ "$ok" != "1" ]; then
    echo "[entrypoint] MariaDB never became reachable" >&2
    exit 1
fi

if [ ! -f /var/www/html/config/config_db.php ]; then
    echo "[entrypoint] installing GLPI via bin/console (no wizard)..."
    if ! php bin/console database:install \
        --db-host="$DB_HOST" --db-name="$DB_NAME" \
        --db-user="$DB_USER" --db-password="$DB_PASS" \
        --default-language=en_GB --no-interaction --force; then
        echo "[entrypoint] database:install failed" >&2
        exit 1
    fi
fi
if [ ! -f /var/www/html/config/config_db.php ]; then
    echo "[entrypoint] install did not produce config/config_db.php" >&2
    exit 1
fi

echo "[entrypoint] planting canary + enabling debug session for admin..."
mysql -h "$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" <<SQL
CREATE TABLE IF NOT EXISTS pcb_canary (id INT PRIMARY KEY, secret VARCHAR(64));
DELETE FROM pcb_canary;
INSERT INTO pcb_canary (id, secret) VALUES (1, '${PCB_FLAG}');
UPDATE glpi_users SET use_mode = 2 WHERE name = 'glpi';
UPDATE glpi_users SET password_forget_token = NULL, password_forget_token_date = NULL WHERE name = 'glpi';
SQL

chown -R www-data:www-data /var/www/html/config /var/www/html/files 2>/dev/null || true
echo "$PCB_FLAG" > /tmp/pcb_ready
echo "[entrypoint] starting Apache"
exec apache2-foreground
