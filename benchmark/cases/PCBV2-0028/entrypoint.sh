#!/bin/bash
# Entrypoint for the REAL TestLink app image. Generates config_db.inc.php (so checkConfiguration()
# does NOT bounce to the installer), waits for the MySQL/MariaDB service, seeds the REAL TestLink
# schema + default data (default admin/admin) from the cloned install/sql/mysql/*.sql on first boot,
# then starts Apache serving the REAL index.php. No source-lift: this only stands up the published
# TestLink so its own index.php::initEnv() reqURI reflection runs over real HTTP.
set -e

DB_HOST="${DB_HOST:-db}"
DB_NAME="${DB_NAME:-testlink}"
DB_USER="${DB_USER:-testlink}"
DB_PASS="${DB_PASS:-testlink}"
WWW=/var/www/html

# 1) config_db.inc.php -> makes checkConfiguration() proceed instead of redirecting to /install.
cat > "$WWW/config_db.inc.php" <<EOF
<?php
define('DB_TYPE', 'mysql');
define('DB_USER', '${DB_USER}');
define('DB_PASS', '${DB_PASS}');
define('DB_HOST', '${DB_HOST}');
define('DB_NAME', '${DB_NAME}');
define('DB_TABLE_PREFIX', '');
EOF

mysql_cmd() { mysql -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" "$@"; }

# 2) wait for the DB.
echo "[entrypoint] waiting for DB at $DB_HOST ..."
for i in $(seq 1 60); do
  if mysql_cmd -e "SELECT 1" >/dev/null 2>&1; then echo "[entrypoint] DB is up"; break; fi
  sleep 3
done

# 3) seed on first boot (real TestLink schema + default data incl. admin/admin).
if ! mysql_cmd -e "SELECT 1 FROM users LIMIT 1" >/dev/null 2>&1; then
  echo "[entrypoint] seeding REAL TestLink schema + default data ..."
  mysql_cmd < "$WWW/install/sql/mysql/testlink_create_tables.sql"
  if [ -f "$WWW/install/sql/mysql/testlink_create_udf0.sql" ]; then
    mysql_cmd < "$WWW/install/sql/mysql/testlink_create_udf0.sql" || true
  fi
  mysql_cmd < "$WWW/install/sql/mysql/testlink_create_default_data.sql"
  echo "[entrypoint] seed complete (admin/admin)"
else
  echo "[entrypoint] schema already present, skipping seed"
fi

# 4) ensure runtime-writable dirs.
mkdir -p /var/testlink/logs
chmod -R 0777 /var/testlink "$WWW/gui/templates_c" "$WWW/upload_area" "$WWW/logs" 2>/dev/null || true
chown -R www-data:www-data "$WWW/gui/templates_c" "$WWW/upload_area" 2>/dev/null || true

echo "[entrypoint] starting Apache (HARNESS_VER=${HARNESS_VER:-?}, TL_REF=${TL_REF:-?})"
exec "$@"
