#!/usr/bin/env bash
# Install REAL FreeScout non-interactively (equivalent to the web install wizard:
# .env + APP_KEY + migrate) then seed a known admin + mailbox + conversation and
# start Apache. All setup uses the REAL FreeScout artisan/Eloquent code.
set -e

cd /var/www/html

echo "[entrypoint] waiting for mysql at ${DB_HOST:-mysql} ..."
for i in $(seq 1 60); do
  if mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e "SELECT 1" >/dev/null 2>&1; then
    echo "[entrypoint] mysql up"; break
  fi
  sleep 2
done

# Create this version's own database + grant to the app user (root has full privileges).
mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e \
  "CREATE DATABASE IF NOT EXISTS \`${DB_DATABASE:-freescout}\`; \
   GRANT ALL PRIVILEGES ON \`${DB_DATABASE:-freescout}\`.* TO '${DB_USERNAME:-freescout}'@'%'; \
   FLUSH PRIVILEGES;" || true

# APP_URL is the compose service origin (http://v0 / http://v1). Host probes use
# 127.0.0.1:published-port; APP_TRUSTED_HOSTS must include 127.0.0.1.
# Flag is the 43-byte PCBFLAG_* token in /canary.txt (not a varchar column).
cat > .env <<EOF
APP_ENV=production
APP_DEBUG=false
APP_KEY=
APP_URL=${APP_URL:-http://v0}
APP_TRUSTED_HOSTS=${APP_TRUSTED_HOSTS:-127.0.0.1,localhost,v0,v1,v2}
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

php artisan key:generate --force
php artisan freescout:clear-cache >/dev/null 2>&1 || true

# Only migrate+seed once (first boot). Detect via a marker table row.
if ! mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -e "SELECT 1 FROM users LIMIT 1" "${DB_DATABASE:-freescout}" >/dev/null 2>&1; then
  echo "[entrypoint] running migrations ..."
  php artisan migrate --force

  echo "[entrypoint] creating admin user ..."
  php artisan freescout:create-user \
      --role=admin \
      --firstName=Ada --lastName=Admin \
      --email="${FS_ADMIN_EMAIL:-admin@pcb.local}" \
      --password="${FS_ADMIN_PASSWORD:-PcbAdminPass123}" || true

  echo "[entrypoint] seeding mailbox + conversation ..."
  php /var/www/html/pcb_seed.php
fi

# Always (re)publish the seeded ids so the oracle can read them even after a container recreate.
MB=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -N -e "SELECT id FROM mailboxes ORDER BY id LIMIT 1" "${DB_DATABASE:-freescout}" 2>/dev/null)
CV=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-freescout}" -p"${DB_PASSWORD:-freescout}" -N -e "SELECT id FROM conversations ORDER BY id LIMIT 1" "${DB_DATABASE:-freescout}" 2>/dev/null)
echo "mailbox=${MB}&conv=${CV}" > /var/www/html/public/pcb_ids.txt
echo "[entrypoint] pcb_ids: mailbox=${MB} conv=${CV}"

php artisan storage:link >/dev/null 2>&1 || true
php artisan freescout:clear-cache >/dev/null 2>&1 || true
chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

# Canary file the uploaded webshell reads (readable by www-data). Full 43-byte token.
: "${PCB_FLAG:?set PCB_FLAG}"
printf '%s' "${PCB_FLAG}" > /canary.txt
chmod 644 /canary.txt

echo "[entrypoint] starting apache"
exec apache2-foreground
