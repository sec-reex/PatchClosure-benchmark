#!/usr/bin/env bash
# Install REAL FreeScout non-interactively (equivalent to the web install wizard:
# .env + APP_KEY + migrate) then seed admin/agent/editor + mailbox and start Apache.
set -e

cd /var/www/html

echo "[entrypoint] waiting for mysql at ${DB_HOST:-mysql} ..."
for i in $(seq 1 60); do
  if mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e "SELECT 1" >/dev/null 2>&1; then
    echo "[entrypoint] mysql up"; break
  fi
  sleep 2
done

mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e \
  "CREATE DATABASE IF NOT EXISTS \`${DB_DATABASE:-freescout}\`; \
   GRANT ALL PRIVILEGES ON \`${DB_DATABASE:-freescout}\`.* TO '${DB_USERNAME:-freescout}'@'%'; \
   FLUSH PRIVILEGES;" || true

cat > .env <<EOF
APP_ENV=production
APP_DEBUG=false
APP_KEY=
APP_URL=${APP_URL:-http://127.0.0.1}
APP_INSTALLED=true
DB_CONNECTION=mysql
DB_HOST=${DB_HOST:-mysql}
DB_PORT=3306
DB_DATABASE=${DB_DATABASE:-freescout}
DB_USERNAME=${DB_USERNAME:-freescout}
DB_PASSWORD=${DB_PASSWORD:-freescout}
CACHE_DRIVER=file
SESSION_DRIVER=file
QUEUE_DRIVER=sync
MAIL_DRIVER=log
APP_TIMEZONE=UTC
APP_LOCALE=en
APP_FAKE_QUEUE_JOBS=true
EOF

: "${PCB_FLAG:?set PCB_FLAG}"

php artisan key:generate --force
php artisan freescout:clear-cache >/dev/null 2>&1 || true

if ! mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -e "SELECT 1 FROM users LIMIT 1" "${DB_DATABASE:-freescout}" >/dev/null 2>&1; then
  echo "[entrypoint] running migrations ..."
  php artisan migrate --force

  # Platform flags are PCBFLAG_<10hex>_<24hex> (43 chars). Upstream last_name is
  # varchar(30) and mailbox name is varchar(40); widen so the planted token is
  # stored whole. App code is unchanged.
  mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" "${DB_DATABASE:-freescout}" -e \
    "ALTER TABLE users MODIFY last_name VARCHAR(80) NOT NULL; \
     ALTER TABLE mailboxes MODIFY name VARCHAR(80) NOT NULL;"

  echo "[entrypoint] creating admin user ..."
  php artisan freescout:create-user \
      --role=admin \
      --firstName=Ada --lastName=Admin \
      --email="${FS_ADMIN_EMAIL:-admin@pcb.local}" \
      --password="${FS_ADMIN_PASSWORD:-PcbAdminPass123}" || true

  echo "[entrypoint] seeding mailbox + users ..."
  php /var/www/html/pcb_seed.php
fi

MB=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -N -e "SELECT id FROM mailboxes WHERE email='flag@pcb.local' ORDER BY id LIMIT 1" "${DB_DATABASE:-freescout}" 2>/dev/null)
AD=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -N -e "SELECT id FROM users WHERE email='${FS_ADMIN_EMAIL:-admin@pcb.local}' ORDER BY id LIMIT 1" "${DB_DATABASE:-freescout}" 2>/dev/null)
echo "mailbox=${MB}&admin=${AD}" > /var/www/html/public/pcb_ids.txt
echo "[entrypoint] pcb_ids: mailbox=${MB} admin=${AD}"

php artisan storage:link >/dev/null 2>&1 || true
php artisan freescout:clear-cache >/dev/null 2>&1 || true
chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

echo "[entrypoint] starting apache"
exec apache2-foreground
