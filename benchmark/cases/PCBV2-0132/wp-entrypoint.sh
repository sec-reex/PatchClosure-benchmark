#!/usr/bin/env bash
# WordPress-plugin recipe entrypoint (PatchClosure-Bench) — READ-EXFIL (SQLi) case.
# One official `wordpress:*-apache` container per version profile. On boot it:
#   1. plants the per-run ${PCB_FLAG} at /flag/pcb_flag.txt (outside docroot) AND in wp_options
#      as option `pcb_secret` — the protected DB row the ticket-status SQL query must never expose,
#   2. installs wp-cli, WordPress core + an `admin`,
#   3. installs JS Help Desk (slug js-support-ticket) at the PINNED ${JSST_VERSION} and activates
#      it — activation creates the js_ticket_* tables AND the `[jssupportticket]` shortcode page
#      `js-support-ticket-controlpanel`; its id is stored in option `pcb_page_id` for the oracle,
#   4. drops a benchmark mu-plugin that turns ON $wpdb->show_errors() so a DB error surfaces in the
#      rendered page (needed for the error-based residual exfil). This is a TEST harness knob, NOT
#      part of JS Help Desk/WP business logic; it does not touch the plugin's query building.
# The differential (CVE-2023-50839 -> CVE-2023-7337) is driven entirely by real, unmodified
# JS Help Desk plugin code (getTicketidForVisitor / validateTicketDetailForVisitor) at runtime.
set -euo pipefail

mkdir -p /flag
rm -f /flag/ready
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
    --url="http://${WPADDR}" --title="PCB JS Help Desk" \
    --admin_user=admin --admin_password=adminpass \
    --admin_email=admin@example.com --skip-email
fi

# Install + activate JS Help Desk at the pinned version. Activation creates the js_ticket_* tables
# and the [jssupportticket] shortcode page `js-support-ticket-controlpanel`.
# Prefer the zip start.sh pre-fetched from downloads.wordpress.org (avoids
# in-container wordpress.org DNS/API failures). Fall back to a host-side curl.
if [ -f /pcb/_run/js-support-ticket.zip ]; then
  wp plugin install /pcb/_run/js-support-ticket.zip --allow-root --force --activate
else
  curl -fsSL -o /tmp/js-support-ticket.zip \
    "https://downloads.wordpress.org/plugin/js-support-ticket.${JSST_VERSION}.zip" \
    || { echo "plugin download failed" >&2; exit 1; }
  wp plugin install /tmp/js-support-ticket.zip --allow-root --force --activate
fi

# --- Canary: the protected secret the ticket-status SQLi must never expose -----------------
wp option update pcb_secret "${PCB_FLAG}" --allow-root

# --- Ensure the shortcode front page exists and record its id ------------------------------
wp eval '
$p = get_page_by_path("js-support-ticket-controlpanel");
if (!$p) {
  $pid = wp_insert_post(array("post_type"=>"page","post_status"=>"publish",
    "post_title"=>"JS Help Desk","post_name"=>"js-support-ticket-controlpanel",
    "post_content"=>"[jssupportticket]"), true);
} else { $pid = $p->ID; }
update_option("pcb_page_id",(int)$pid);
echo "page_id=".$pid."\n";
' --allow-root

# --- Benchmark test harness mu-plugin: surface DB errors so error-based SQLi reflects -------
# (NOT part of JS Help Desk/WP; does not alter any plugin query. It only flips wpdb->show_errors
#  so the extractvalue() XPATH error — carrying the exfiltrated secret — is rendered in the page.)
mkdir -p wp-content/mu-plugins
cat > wp-content/mu-plugins/pcb-show-db-errors.php <<'PHP'
<?php
/* PatchClosure-Bench test harness: turn ON visible wpdb errors so an error-based SQL injection
 * reflects its extractvalue() payload into the HTTP response. No plugin/business code is edited. */
add_action('plugins_loaded', function () {
    if (isset($GLOBALS['wpdb'])) { $GLOBALS['wpdb']->show_errors(); }
}, 0);
PHP

chown -R www-data:www-data /var/www/html
touch /flag/ready
echo "[pcb] JS Help Desk ${JSST_VERSION} ready on ${WPADDR}"
exec apache2-foreground
