#!/bin/bash
# Entrypoint for real Cacti installation (cacti-cve-2025-24368).
# Waits for MariaDB, imports Cacti schema, configures the app, seeds benchmark data, starts Apache.
set -e

DB_HOST="${DB_HOST:-db}"
DB_USER="${DB_USER:-cacti}"
DB_PASS="${DB_PASS:-cacti}"
DB_NAME="${DB_NAME:-cacti}"
export MYSQL_PWD="$DB_PASS"

# mysql client alias with SSL disabled (MariaDB in Docker doesn't use SSL)
MYSQL="mysql --skip-ssl -h $DB_HOST -u $DB_USER $DB_NAME"

echo "[pcb-entrypoint] Waiting for MariaDB at $DB_HOST..."
TRIES=0
until $MYSQL -e "SELECT 1" >/dev/null 2>&1; do
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -gt 120 ]; then
        echo "[pcb-entrypoint] ERROR: MariaDB not ready after 240s, aborting."
        exit 1
    fi
    sleep 2
done
echo "[pcb-entrypoint] MariaDB ready."

# --- Determine Cacti version from source ---
CACTI_VER=$(cat /var/www/html/cacti/include/cacti_version 2>/dev/null | tr -d '[:space:]')
if [ -z "$CACTI_VER" ]; then
    CACTI_VER="1.2.27"  # fallback
fi
echo "[pcb-entrypoint] Cacti version from source: $CACTI_VER"

# --- Import schema if not yet loaded ---
HAS_VERSION=$($MYSQL -N -e \
    "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='$DB_NAME' AND TABLE_NAME='version'" 2>/dev/null || echo "0")

if [ "$HAS_VERSION" = "0" ] || [ "$HAS_VERSION" = "" ]; then
    echo "[pcb-entrypoint] Importing Cacti schema from cacti.sql..."
    $MYSQL < /var/www/html/cacti/cacti.sql
    echo "[pcb-entrypoint] Schema imported."
fi

# --- Set DB version to match code (prevents installer redirect) ---
$MYSQL -e "UPDATE version SET cacti='$CACTI_VER';" 2>/dev/null || true

# --- Write Cacti config.php ---
cat > /var/www/html/cacti/include/config.php << CFGEOF
<?php
\$database_type     = 'mysql';
\$database_default  = '${DB_NAME}';
\$database_hostname = '${DB_HOST}';
\$database_username = '${DB_USER}';
\$database_password = '${DB_PASS}';
\$database_port     = '3306';
\$database_retries  = 5;
\$database_ssl      = false;
\$database_ssl_key  = '';
\$database_ssl_cert = '';
\$database_ssl_ca   = '';
\$url_path = '/';
CFGEOF
chown www-data:www-data /var/www/html/cacti/include/config.php

# --- Configure admin user (skip forced password change) ---
ADMIN_HASH=$(php -r "echo password_hash('admin', PASSWORD_BCRYPT);")
$MYSQL -e "
    UPDATE user_auth SET password='$ADMIN_HASH', must_change_password='' WHERE username='admin';
" 2>/dev/null || true

# Grant admin full realm access (automation pages require specific realm IDs)
$MYSQL -e "
    INSERT IGNORE INTO user_auth_realm (realm_id, user_id)
    SELECT realm_id, 1 FROM (
        SELECT 1 AS realm_id UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5
        UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10 UNION SELECT 11
        UNION SELECT 12 UNION SELECT 13 UNION SELECT 14 UNION SELECT 15 UNION SELECT 16
        UNION SELECT 17 UNION SELECT 18 UNION SELECT 19 UNION SELECT 20 UNION SELECT 21
        UNION SELECT 22 UNION SELECT 23 UNION SELECT 24 UNION SELECT 25 UNION SELECT 26
        UNION SELECT 27 UNION SELECT 28 UNION SELECT 73 UNION SELECT 74 UNION SELECT 75
        UNION SELECT 76 UNION SELECT 77 UNION SELECT 78 UNION SELECT 100 UNION SELECT 101
        UNION SELECT 102 UNION SELECT 103 UNION SELECT 104 UNION SELECT 105
    ) realms;
" 2>/dev/null || true

# --- Seed the PCB benchmark data ---
# pcb_secrets: the protected row carrying ${PCB_FLAG}; automation queries never SELECT it
$MYSQL -e "
    CREATE TABLE IF NOT EXISTS pcb_secrets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        secret VARCHAR(255) NOT NULL
    );
    DELETE FROM pcb_secrets;
    INSERT INTO pcb_secrets (id, secret) VALUES (1, '${PCB_FLAG:-PCB_UNSET}');
"

# Seed a host device for the automation matching query to find
$MYSQL -e "
    INSERT INTO host (id, poller_id, site_id, hostname, description, disabled, status, host_template_id, deleted)
    VALUES (99, 1, 0, 'localhost-monitor', 'PCB monitored device', '', 3, 1, '')
    ON DUPLICATE KEY UPDATE hostname='localhost-monitor';
" 2>/dev/null || true

# Create a graph tree for automation to reference
$MYSQL -e "
    INSERT INTO graph_tree (id, name, enabled, sort_type, last_modified, user_id)
    VALUES (99, 'PCB Test Tree', 'on', 1, NOW(), 1)
    ON DUPLICATE KEY UPDATE name='PCB Test Tree';
" 2>/dev/null || true

# Create the automation tree rule that display_matching_trees will process
$MYSQL -e "
    INSERT INTO automation_tree_rules (id, name, tree_id, tree_item_id, leaf_type, host_grouping_type, enabled, sequence)
    VALUES (99, 'PCB Test Rule', 99, 0, 3, 1, 'on', 1)
    ON DUPLICATE KEY UPDATE name='PCB Test Rule';
" 2>/dev/null || true

# --- Set Cacti operational settings to avoid warnings ---
$MYSQL -e "
    REPLACE INTO settings (name, value) VALUES
    ('path_rrdtool', '/usr/bin/rrdtool'),
    ('path_php_binary', '/usr/local/bin/php'),
    ('path_snmpwalk', '/usr/bin/snmpwalk'),
    ('path_snmpget', '/usr/bin/snmpget'),
    ('path_snmpbulkwalk', '/usr/bin/snmpbulkwalk'),
    ('path_snmpgetnext', '/usr/bin/snmpgetnext'),
    ('path_snmptrap', '/usr/bin/snmptrap'),
    ('path_cactilog', '/var/www/html/cacti/log/cacti.log'),
    ('poller_type', '1'),
    ('log_destination', '1');
" 2>/dev/null || true

echo "[pcb-entrypoint] Cacti setup complete (version=$CACTI_VER). Starting Apache."
exec apache2-foreground
