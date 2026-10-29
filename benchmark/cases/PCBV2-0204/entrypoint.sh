#!/bin/bash
set -euo pipefail

echo "${PCB_FLAG}" > /canary.txt
chmod 644 /canary.txt
echo "${PCB_FLAG}" > /tmp/pcb_canary.txt
chmod 644 /tmp/pcb_canary.txt

echo "[entrypoint] Waiting for MySQL at ${MYSQL_HOST}..."
for _ in $(seq 1 60); do
    if mysqladmin ping -h "${MYSQL_HOST}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" --skip-ssl --silent 2>/dev/null; then
        break
    fi
    sleep 2
done
mysqladmin ping -h "${MYSQL_HOST}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" --skip-ssl --silent
echo "[entrypoint] MySQL is ready."

cd /var/www/html

already_installed() {
    if [ ! -f config.php ] || ! grep -q "dbconfig" config.php 2>/dev/null; then
        return 1
    fi
    mysql --skip-ssl -h "${MYSQL_HOST}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
        -N -e "SELECT COUNT(*) FROM ${MYSQL_DATABASE}.users" 2>/dev/null | grep -qE '^[1-9]'
}

if already_installed; then
    echo "[entrypoint] SuiteCRM already installed; skipping silent install."
else
    echo "[entrypoint] Recreating database for silent install..."
    mysql --skip-ssl -h "${MYSQL_HOST}" -uroot -proot -e \
        "DROP DATABASE IF EXISTS ${MYSQL_DATABASE}; CREATE DATABASE ${MYSQL_DATABASE} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; GRANT ALL ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'%'; FLUSH PRIVILEGES;"

    sed -i "s/'installer_locked'.*=>.*true/'installer_locked' => false/" config.php 2>/dev/null || true

    echo "[entrypoint] Writing config_si.php..."
    cat > config_si.php <<SIEOF
<?php
\$sugar_config_si = array(
    'setup_db_host_name' => '${MYSQL_HOST}',
    'setup_db_sugarsales_user' => '${MYSQL_USER}',
    'setup_db_sugarsales_password' => '${MYSQL_PASSWORD}',
    'setup_db_database_name' => '${MYSQL_DATABASE}',
    'setup_db_type' => 'mysql',
    'setup_db_pop_demo_data' => false,
    'setup_db_create_database' => true,
    'setup_db_drop_tables' => true,
    'setup_db_admin_user_name' => 'root',
    'setup_db_admin_password' => 'root',
    'setup_site_url' => 'http://127.0.0.1',
    'setup_site_admin_user_name' => 'admin',
    'setup_site_admin_password' => 'Admin123!',
    'setup_license_key' => '',
    'setup_site_sugarbeet_automatic_checks' => false,
    'default_currency_iso4217' => 'USD',
    'default_currency_name' => 'US Dollar',
    'default_currency_significant_digits' => '2',
    'default_currency_symbol' => '\$',
    'default_date_format' => 'Y-m-d',
    'default_time_format' => 'H:i',
    'default_decimal_seperator' => '.',
    'default_export_charset' => 'UTF-8',
    'default_language' => 'en_us',
    'default_locale_name_format' => 's f l',
    'default_number_grouping_seperator' => ',',
    'export_delimiter' => ',',
    'setup_system_name' => 'SuiteCRM',
);
SIEOF
    chown www-data:www-data config_si.php

    echo "[entrypoint] Starting Apache for silent install..."
    apache2ctl start
    for _ in $(seq 1 30); do
        if curl -sf -o /dev/null --max-time 3 http://127.0.0.1/install.php; then
            break
        fi
        sleep 1
    done

    echo "[entrypoint] Triggering silent install..."
    RESULT=""
    for i in $(seq 1 8); do
        RESULT="$(curl -sS -o /tmp/install_out.html -w "%{http_code}" --max-time 300 \
            "http://127.0.0.1/install.php?goto=SilentInstall&cli=true" || true)"
        echo "[entrypoint] Install attempt $i: HTTP ${RESULT}"
        if already_installed; then
            echo "[entrypoint] Install completed."
            break
        fi
        sleep 8
    done

    apache2ctl stop || true
    sleep 2

    if ! already_installed; then
        echo "[entrypoint] FATAL: silent install did not produce a working SuiteCRM." >&2
        head -80 /tmp/install_out.html >&2 || true
        exit 1
    fi
fi

if [ -f config.php ]; then
    php -r "
        \$config = file_get_contents('config.php');
        if (strpos(\$config, 'installer_locked') === false) {
            \$config = str_replace(');', \"    'installer_locked' => true,\n);\", \$config);
        } else {
            \$config = preg_replace(\"/'installer_locked'\\s*=>\\s*false/\", \"'installer_locked' => true\", \$config);
        }
        file_put_contents('config.php', \$config);
    "
fi

cat > /var/www/html/config_override.php <<'OVEOF'
<?php
$sugar_config['moduleInstaller']['packageScan'] = true;
$sugar_config['http_referer']['list'][] = '127.0.0.1';
$sugar_config['http_referer']['list'][] = 'localhost';
$sugar_config['http_referer']['actions'] = array(
    'index', 'ListView', 'DetailView', 'EditView', 'oauth', 'authorize',
    'Authenticate', 'Login', 'SupportPortal', 'UpgradeWizard', 'HandleAjaxCall',
);
$sugar_config['verify_client_ip'] = false;
OVEOF
chown www-data:www-data /var/www/html/config_override.php

php -r "
  \$cmd = 'mysql --skip-ssl -h ${MYSQL_HOST} -uroot -proot ${MYSQL_DATABASE} -sN -e \"SELECT contents FROM user_preferences WHERE assigned_user_id=1 AND category=\\\"global\\\" LIMIT 1\"';
  \$prefs_b64 = trim(shell_exec(\$cmd) ?: '');
  if (\$prefs_b64) {
    \$prefs = @unserialize(base64_decode(\$prefs_b64));
    if (is_array(\$prefs)) {
      \$prefs['ut'] = '1';
      \$prefs['timezone'] = 'UTC';
      \$new = base64_encode(serialize(\$prefs));
      \$esc = str_replace(\"'\", \"''\", \$new);
      shell_exec('mysql --skip-ssl -h ${MYSQL_HOST} -uroot -proot ${MYSQL_DATABASE} -e \"UPDATE user_preferences SET contents=\\\"' . \$esc . '\\\" WHERE assigned_user_id=1 AND category=\\\"global\\\"\"');
      fwrite(STDERR, \"[entrypoint] Admin preferences ut=1 timezone=UTC\n\");
    }
  }
" || true

mkdir -p /var/www/html/upload/upgrades/module /var/www/html/cache /var/www/html/custom/modules
chown -R www-data:www-data /var/www/html/upload /var/www/html/cache /var/www/html/custom \
    /var/www/html/config.php /var/www/html/config_override.php
chmod -R 775 /var/www/html/upload /var/www/html/cache /var/www/html/custom

touch /tmp/pcb_ready
echo "[entrypoint] Starting Apache (foreground)..."
exec apache2-foreground
