#!/usr/bin/env bash
# WordPress-plugin recipe entrypoint (PatchClosure-Bench) — AUTHZ-SEEDED case.
# One official `wordpress:*-apache` container per version profile. On boot it:
#   1. plants the per-run ${PCB_FLAG} at /flag/pcb_flag.txt OUTSIDE the docroot,
#   2. drops a mu-plugin exposing an ADMIN-ONLY admin-ajax action `pcb_secret`
#      that returns that flag ONLY to a caller with `manage_options`
#      (the victim secret in a protected place — the canary),
#   3. installs wp-cli, WordPress core, an `admin` + a low-priv `viewer` (attacker),
#   4. installs the ASE plugin at the PINNED ${ASE_VERSION} from wordpress.org and
#      ENABLES its "View Admin as Role" module via ASE's OWN option (env config,
#      no plugin/core source edit).
# The differential (CVE-2024-43333 -> CVE-2026-12083) is driven entirely by the
# real plugin code at runtime; nothing in ASE/WP business code is modified.
set -euo pipefail

mkdir -p /flag
printf '%s' "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt

if [ ! -x /usr/local/bin/wp ]; then
  curl -fsSL -o /usr/local/bin/wp \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
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
until php -r '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME")); exit($c?0:1);'; do sleep 3; done

if ! wp core is-installed --allow-root >/dev/null 2>&1; then
  wp core install --allow-root \
    --url="http://${WPADDR}" --title="PCB ASE" \
    --admin_user=admin --admin_password=adminpass \
    --admin_email=admin@example.com --skip-email
  # `viewer` = the attacker account (a demoted admin). Created as subscriber;
  # each probe re-establishes its role/meta via the real plugin behaviour.
  wp user create viewer viewer@example.com --allow-root \
    --role=subscriber --user_pass=viewerpass
fi

# Prefer the zip start.sh pre-fetched from downloads.wordpress.org (avoids
# in-container wordpress.org DNS/API failures). Fall back to a host-side curl.
if [ -f /pcb/_run/admin-site-enhancements.zip ]; then
  wp plugin install /pcb/_run/admin-site-enhancements.zip --allow-root --force --activate
else
  curl -fsSL -o /tmp/admin-site-enhancements.zip \
    "https://downloads.wordpress.org/plugin/admin-site-enhancements.${ASE_VERSION}.zip" \
    || { echo "plugin download failed" >&2; exit 1; }
  wp plugin install /tmp/admin-site-enhancements.zip --allow-root --force --activate
fi

# Enable ASE's "View Admin as Role" module via the plugin's OWN option (env config).
wp eval 'update_option("admin_site_enhancements", array_merge((array) get_option("admin_site_enhancements", array()), array("view_admin_as_role"=>true)), true);' --allow-root

# --- Canary: admin-only protected resource holding ${PCB_FLAG} (NOT app code) ---
mkdir -p wp-content/mu-plugins
cat > wp-content/mu-plugins/pcb-flag-endpoint.php <<'PHP'
<?php
/* PatchClosure-Bench canary (NOT part of ASE/WP): an admin-only resource that
 * returns the planted victim secret ONLY to a caller holding `manage_options`.
 * A low-priv subscriber gets 403; an administrator gets the flag. This is the
 * cross-privilege oracle: reading it proves the caller reached administrator. */
add_action('wp_ajax_pcb_secret', function () {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(array('msg' => 'forbidden'), 403);
    }
    wp_send_json_success(array('flag' => trim(@file_get_contents('/flag/pcb_flag.txt'))));
});
PHP

chown -R www-data:www-data /var/www/html
echo "[pcb] ASE ${ASE_VERSION} ready on ${WPADDR}"
exec apache2-foreground
