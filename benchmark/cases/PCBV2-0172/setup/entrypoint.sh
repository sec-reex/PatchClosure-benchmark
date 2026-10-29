#!/bin/bash
set -e

DB_HOST="${DB_HOST:-db}"
DB_PASS="${MYSQL_ROOT_PASSWORD:-pcbroot}"
DB_NAME="${DB_NAME:-pimcore}"
VER="${PCB_VER:-v1}"

echo "[pcb-pimcore:$VER] Waiting for MySQL ($DB_HOST)..."
for i in $(seq 1 180); do
    if php -r "try { new PDO('mysql:host='.'$DB_HOST','root','$DB_PASS'); echo 'ok'; } catch(Exception \$e) { exit(1); }" 2>/dev/null | grep -q ok; then
        echo "[pcb-pimcore:$VER] MySQL is ready after ${i}s."
        break
    fi
    if [ "$i" = "180" ]; then
        echo "[pcb-pimcore:$VER] FATAL: MySQL never came up."
        exit 1
    fi
    sleep 1
done

# Create database (use PHP since mysql CLI may not be available)
php -r "
\$p = new PDO('mysql:host=$DB_HOST', 'root', '$DB_PASS');
\$p->exec('CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
echo 'DB $DB_NAME created/ok\n';
" 2>&1

cd /var/www/html

# ---- Register SimpleBackendSearchBundle in the Kernel (Pimcore 11 only) ----
PIMCORE_MAJOR="${PIMCORE_MAJOR:-11}"
if [ "$PIMCORE_MAJOR" = "11" ] && ! grep -q 'SimpleBackendSearchBundle' src/Kernel.php 2>/dev/null; then
    echo "[pcb-pimcore:$VER] Registering SimpleBackendSearchBundle in Kernel..."
    sed -i 's/use Pimcore\\HttpKernel\\BundleCollection\\BundleCollection;/use Pimcore\\HttpKernel\\BundleCollection\\BundleCollection;\nuse Pimcore\\Bundle\\SimpleBackendSearchBundle\\PimcoreSimpleBackendSearchBundle;/' src/Kernel.php
    sed -i 's/$collection->addBundle(new PimcoreAdminBundle(), 60);/$collection->addBundle(new PimcoreAdminBundle(), 60);\n        $collection->addBundle(new PimcoreSimpleBackendSearchBundle(), 10);/' src/Kernel.php
    # Clear cache after kernel change
    php bin/console cache:clear --no-warmup 2>/dev/null || true
fi

# ---- Pimcore install ----
if [ ! -f var/.pcb_installed ]; then
    echo "[pcb-pimcore:$VER] Running Pimcore installer..."

    # Write .env.local for Symfony
    cat > .env.local <<ENVEOF
DATABASE_URL="mysql://root:${DB_PASS}@${DB_HOST}:3306/${DB_NAME}"
APP_ENV=dev
APP_DEBUG=1
PIMCORE_DEV_MODE=true
ENVEOF

    # Pimcore 11: Doctrine DBAL doesn't auto-read DATABASE_URL; wire it explicitly
    if [ "$PIMCORE_MAJOR" = "11" ]; then
        mkdir -p config/local
        cat > config/local/database.yaml <<DBEOF
doctrine:
    dbal:
        url: 'mysql://root:${DB_PASS}@${DB_HOST}:3306/${DB_NAME}'
DBEOF
        echo "[pcb-pimcore:$VER] Created config/local/database.yaml (direct URL)"
    fi

    # Clear Symfony cache
    php bin/console cache:clear --no-warmup 2>/dev/null || true

    # Run installer (try both paths for compatibility)
    echo "[pcb-pimcore:$VER] Running pimcore-install..."
    php vendor/bin/pimcore-install \
        --admin-username=admin \
        --admin-password=admin \
        --mysql-host-socket="$DB_HOST" \
        --mysql-port=3306 \
        --mysql-username=root \
        --mysql-password="$DB_PASS" \
        --mysql-database="$DB_NAME" \
        --ignore-existing-config \
        --no-interaction 2>&1 || {
        echo "[pcb-pimcore:$VER] pimcore-install exited non-zero, trying alternate..."
        php bin/console pimcore:install \
            --admin-username=admin \
            --admin-password=admin \
            --mysql-host-socket="$DB_HOST" \
            --mysql-port=3306 \
            --mysql-username=root \
            --mysql-password="$DB_PASS" \
            --mysql-database="$DB_NAME" \
            --no-interaction 2>&1 || echo "[pcb-pimcore:$VER] Alternate installer also failed."
    }

    # Install the search bundle (creates its DB tables; Pimcore 11 only)
    if [ "$PIMCORE_MAJOR" = "11" ]; then
        echo "[pcb-pimcore:$VER] Installing PimcoreSimpleBackendSearchBundle..."
        php bin/console pimcore:bundle:install PimcoreSimpleBackendSearchBundle --no-cache-clear 2>&1 || echo "[pcb-pimcore:$VER] WARNING: search bundle install failed (may already be installed)"
    fi

    echo "[pcb-pimcore:$VER] Creating object class and brick..."
    php /opt/pimcore-setup/setup_objects.php 2>&1 || {
        echo "[pcb-pimcore:$VER] PHP setup failed, trying SQL fallback..."
        php /opt/pimcore-setup/setup_objects_sql.php 2>&1 || echo "[pcb-pimcore:$VER] SQL fallback also failed."
    }

    # Seed pcb_secret table
    echo "[pcb-pimcore:$VER] Seeding pcb_secret table..."
    php -r "
\$p = new PDO('mysql:host=$DB_HOST;dbname=$DB_NAME', 'root', '$DB_PASS');
\$p->exec('CREATE TABLE IF NOT EXISTS pcb_secret (id INT PRIMARY KEY, flag VARCHAR(128))');
\$s = \$p->prepare('REPLACE INTO pcb_secret (id, flag) VALUES (1, ?)');
\$s->execute([getenv('PCB_FLAG')]);
echo 'pcb_secret seeded\n';
" 2>&1

    # Pimcore 11: warm the Symfony cache with correct DATABASE_URL so web requests use TCP
    if [ "$PIMCORE_MAJOR" = "11" ]; then
        echo "[pcb-pimcore:$VER] Warming Symfony cache..."
        php bin/console cache:warmup 2>&1 || true
    fi

    touch var/.pcb_installed
    echo "[pcb-pimcore:$VER] Installation complete."
else
    echo "[pcb-pimcore:$VER] Already installed, updating flag..."
    # Ensure database.yaml exists on restart (volume mount is ro, file is inside container)
    if [ "$PIMCORE_MAJOR" = "11" ] && [ ! -f config/local/database.yaml ]; then
        mkdir -p config/local
        cat > config/local/database.yaml <<DBEOF
doctrine:
    dbal:
        url: 'mysql://root:${DB_PASS}@${DB_HOST}:3306/${DB_NAME}'
DBEOF
        php bin/console cache:warmup 2>&1 || true
    fi
    php -r "
\$p = new PDO('mysql:host=$DB_HOST;dbname=$DB_NAME', 'root', '$DB_PASS');
\$s = \$p->prepare('REPLACE INTO pcb_secret (id, flag) VALUES (1, ?)');
\$s->execute([getenv('PCB_FLAG')]);
echo 'flag updated\n';
" 2>&1 || true
fi

# PatchClosure: publish the readiness marker ONLY now that install+seed is done. It was previously
# baked into the image (Dockerfile) so it returned "OK" instantly — the oracle's _wait_ready was
# satisfied in ~6s, before the DB config existed, and its auth POST then fell back to a unix socket
# ([2002] No such file or directory). Writing it post-install makes readiness honest.
mkdir -p /var/www/html/public
echo OK > /var/www/html/public/pcb_health.txt

# Set permissions
chown -R www-data:www-data /var/www/html/var 2>/dev/null || true
chmod -R 775 /var/www/html/var 2>/dev/null || true

# Create .htaccess for Symfony URL rewriting (required for admin routes)
if [ ! -f public/.htaccess ]; then
    cat > public/.htaccess <<'HTEOF'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^(.*)$ index.php [QSA,L]
</IfModule>
HTEOF
    echo "[pcb-pimcore:$VER] Created .htaccess"
fi

echo "[pcb-pimcore:$VER] Starting Apache on :80..."
exec apache2-foreground
