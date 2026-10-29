#!/usr/bin/env bash
# Reusable WordPress-plugin recipe entrypoint (PatchClosure-Bench).
# One official `wordpress:*-apache` container per version profile. On boot it:
#   1. plants the per-run ${PCB_FLAG} at /flag/pcb_flag.txt OUTSIDE the docroot
#      (environment canary -> only code-exec can read it; NOT app code),
#   2. installs wp-cli, WordPress core, an admin + a low-priv `subscriber`,
#   3. installs the plugin at the PINNED ${FO_VERSION} from wordpress.org
#      (recipe-based: no vendored plugin source committed),
#   4. drops a must-use plugin that lowers FileOrganizer's access capability to
#      `read` via the plugin's OWN documented `fileorganizer_get_capability`
#      filter -- exactly how the Pro add-on grants file-manager access to lower
#      roles. This is environment configuration, NOT a plugin/core source edit.
# Later WP-plugin cases copy this file verbatim and only change FO_VERSION / slug.
set -euo pipefail

mkdir -p /flag
printf '%s' "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt

if [ ! -x /usr/local/bin/wp ]; then
  if [ -f /pcb/_run/wp-cli.phar ]; then
    cp /pcb/_run/wp-cli.phar /usr/local/bin/wp
  else
    ok=0
    for i in 1 2 3 4 5; do
      if curl -fsSL -o /usr/local/bin/wp \
        https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar; then
        ok=1
        break
      fi
      echo "[pcb] wp-cli download retry $i" >&2
      sleep 4
    done
    if [ "$ok" != "1" ]; then
      echo "[pcb] wp-cli download failed" >&2
      exit 1
    fi
  fi
  chmod +x /usr/local/bin/wp
fi

if [ ! -f /var/www/html/wp-load.php ]; then
  cp -a /usr/src/wordpress/. /var/www/html/
fi
cd /var/www/html
chown -R www-data:www-data /var/www/html

WPADDR="127.0.0.1:${WP_HOST_PORT}"

wp config create --allow-root --force --skip-check \
  --dbhost="${WORDPRESS_DB_HOST}" --dbname="${WORDPRESS_DB_NAME}" \
  --dbuser="${WORDPRESS_DB_USER}" --dbpass="${WORDPRESS_DB_PASSWORD}"

echo "[pcb] waiting for database ${WORDPRESS_DB_HOST} ..."
# NB: the wordpress image ships no mysql client binaries, so `wp db check`
# (which shells out to mysqlcheck) can't be used -- probe via PHP mysqli instead.
until php -r '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME")); exit($c?0:1);'; do sleep 3; done

if ! wp core is-installed --allow-root >/dev/null 2>&1; then
  wp core install --allow-root \
    --url="http://${WPADDR}" --title="PCB FileOrganizer" \
    --admin_user=admin --admin_password=adminpass \
    --admin_email=admin@example.com --skip-email
  wp user create subscriber sub@example.com --allow-root \
    --role=subscriber --user_pass=subpass
fi

# Prefer the zip start.sh staged from fetch_source (no extra wordpress.org hit).
if [ -f /pcb/_run/fileorganizer.zip ]; then
  wp plugin install /pcb/_run/fileorganizer.zip --allow-root --force --activate
else
  ok=0
  for i in 1 2 3 4 5; do
    if curl -fsSL -o /tmp/fileorganizer.zip \
      "https://downloads.wordpress.org/plugin/fileorganizer.${FO_VERSION}.zip"; then
      ok=1
      break
    fi
    echo "[pcb] plugin download retry $i" >&2
    sleep 4
  done
  if [ "$ok" != "1" ]; then
    echo "plugin download failed" >&2
    exit 1
  fi
  wp plugin install /tmp/fileorganizer.zip --allow-root --force --activate
fi

mkdir -p wp-content/mu-plugins
cat > wp-content/mu-plugins/pcb-fileorganizer-cap.php <<'PHP'
<?php
/* PatchClosure-Bench env config (NOT app code): grant the low-priv subscriber
 * test user file-manager access via FileOrganizer's OWN public extension filter
 * -- the same hook its Pro add-on uses to extend access to lower roles. This
 * makes the CVE-2024-7985 `upload.presave` file-type check actually apply (it is
 * skipped for `activate_plugins`/admin users), so the differential is genuine. */
add_filter('fileorganizer_get_capability', function ($cap) { return 'read'; });
PHP

chown -R www-data:www-data /var/www/html
echo "[pcb] FileOrganizer ${FO_VERSION} ready on ${WPADDR}"
exec apache2-foreground
