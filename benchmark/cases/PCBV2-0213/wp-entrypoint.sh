#!/usr/bin/env bash
# WordPress-plugin recipe entrypoint (PatchClosure-Bench) — READ-EXFIL (mfunc RCE) case.
# One official `wordpress:*-apache` container per version profile. On boot it:
#   1. plants the per-run ${PCB_FLAG} at /flag/pcb_flag.txt OUTSIDE the docroot,
#   2. installs wp-cli, WordPress core + an admin,
#   3. installs the WHOLE WP Super Cache plugin at PINNED ${WPSC_VERSION} from
#      wordpress.org and activates it (real product, not a snippet harness),
#   4. turns Super Cache ON (WP_CACHE + WPCACHEHOME + advanced-cache.php +
#      wp-cache-config.php via the plugin's own setup helpers; PHP cache serving),
#   5. publishes one commentable post and a classic theme so comments render
#      through comment_text (where no_mfunc_in_comments is hooked on V1/V2).
# The differential (CVE-2013-2009 -> CVE-2013-2011) is driven entirely by real,
# unmodified WP Super Cache bytes at runtime.
set -euo pipefail

mkdir -p /flag
rm -f /flag/ready
printf '%s' "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt

if [ ! -x /usr/local/bin/wp ]; then
  # PatchClosure: raw.githubusercontent.com is one of the hosts this gateway resets for the default
  # TLS1.3 ClientHello that bullseye openssl-1.1.1 curl sends (curl 35 SSL_ERROR_SYSCALL). Without
  # wp-cli the whole entrypoint dies under `set -e` -> WP never set up -> exploit can't reach the
  # flag (seed_v0_reaches=false). Forcing --tls-max 1.2 reshapes the hello -> 200.
  curl --tls-max 1.2 -fsSL -m 120 --connect-timeout 30 --retry 3 -o /usr/local/bin/wp \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  chmod +x /usr/local/bin/wp
fi

if [ ! -f /var/www/html/wp-load.php ]; then
  cp -a /usr/src/wordpress/. /var/www/html/
fi
cd /var/www/html
chown -R www-data:www-data /var/www/html

WPADDR="127.0.0.1:${WP_HOST_PORT}"
WPSC_HOME="/var/www/html/wp-content/plugins/wp-super-cache/"

wp config create --allow-root --force --skip-check \
  --dbhost="${WORDPRESS_DB_HOST}" --dbname="${WORDPRESS_DB_NAME}" \
  --dbuser="${WORDPRESS_DB_USER}" --dbpass="${WORDPRESS_DB_PASSWORD}"

# Super Cache drop-in is loaded from wp-settings.php only when WP_CACHE is true
# and WPCACHEHOME points at the plugin directory (advanced-cache.php stub).
wp config set WP_CACHE true --raw --type=constant --allow-root
wp config set WPCACHEHOME "${WPSC_HOME}" --type=constant --allow-root

echo "[pcb] waiting for database ${WORDPRESS_DB_HOST} ..."
until php -r '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME")); exit($c?0:1);'; do sleep 3; done

if ! wp core is-installed --allow-root >/dev/null 2>&1; then
  wp core install --allow-root \
    --url="http://${WPADDR}" --title="PCB WP Super Cache" \
    --admin_user=admin --admin_password=adminpass \
    --admin_email=admin@example.com --skip-email
fi

# Prefer the zip start.sh pre-fetched from downloads.wordpress.org (avoids
# in-container wordpress.org DNS/API failures). Fall back to a host-side curl.
# Install first without activate so we can drop the plugin's own advanced-cache.php
# + config (wp-cli eval cannot see plugin file-scope $wp_cache_file).
if [ -f /pcb/_run/wp-super-cache.zip ]; then
  wp plugin install /pcb/_run/wp-super-cache.zip --allow-root --force
else
  curl --tls-max 1.2 -fsSL -m 120 --connect-timeout 30 --retry 3 -o /tmp/wp-super-cache.zip \
    "https://downloads.wordpress.org/plugin/wp-super-cache.${WPSC_VERSION}.zip" \
    || { echo "plugin download failed" >&2; exit 1; }
  wp plugin install /tmp/wp-super-cache.zip --allow-root --force
fi

PLUGIN_DIR="wp-content/plugins/wp-super-cache"
if [ ! -f "${PLUGIN_DIR}/advanced-cache.php" ] || [ ! -f "${PLUGIN_DIR}/wp-cache-config-sample.php" ]; then
  echo "whole WP Super Cache plugin missing under ${PLUGIN_DIR}" >&2
  ls -la wp-content/plugins >&2 || true
  exit 1
fi

# Same files the plugin copies from the settings screen: drop-in + config.
cp "${PLUGIN_DIR}/advanced-cache.php" wp-content/advanced-cache.php
cp "${PLUGIN_DIR}/wp-cache-config-sample.php" wp-content/wp-cache-config.php
php -r '
$f = "/var/www/html/wp-content/wp-cache-config.php";
$s = file_get_contents($f);
$repl = array(
  "\$cache_enabled = false;" => "\$cache_enabled = true;",
  "\$super_cache_enabled = false;" => "\$super_cache_enabled = true;",
  "\$cache_compression = 0;" => "\$cache_compression = 0;",
  "\$wp_cache_not_logged_in = 0;" => "\$wp_cache_not_logged_in = 0;",
  "\$wp_cache_mutex_disabled = 1;" => "\$wp_cache_mutex_disabled = 1;",
);
foreach ($repl as $a => $b) { $s = str_replace($a, $b, $s); }
if (strpos($s, "\$wp_cache_mod_rewrite") === false) {
  $s = str_replace("?>", "\$wp_cache_mod_rewrite = 0;\n\$wp_cache_slash_check = 1;\n?>", $s);
}
file_put_contents($f, $s);
'
mkdir -p wp-content/cache/supercache wp-content/cache/meta wp-content/cache/blogs
wp plugin activate wp-super-cache --allow-root
test -f wp-content/advanced-cache.php && test -f wp-content/wp-cache-config.php \
  || { echo "cache drop-in/config missing" >&2; exit 1; }
echo "[pcb] WP Super Cache drop-in + config in place (PHP serving)"

# Classic theme so comments render via wp_list_comments / comment_text.
wp theme install twentytwentyone --allow-root --activate || true
wp theme activate twentytwentyone --allow-root || true

wp rewrite structure '/%postname%/' --allow-root --hard
wp option update permalink_structure '/%postname%/' --allow-root

# Guest comments, no moderation, so the HTTP comment path is the product path.
wp option update default_comment_status open --allow-root
wp option update comment_moderation 0 --allow-root
wp option update comment_previously_approved 0 --allow-root
wp option update comment_whitelist 0 --allow-root || true
wp option update require_name_email 0 --allow-root
wp option update moderation_notify 0 --allow-root
wp option update comments_notify 0 --allow-root
wp option update close_comments_for_old_posts 0 --allow-root

# One published post the attacker comments on (idempotent).
wp eval '
$existing = get_page_by_path("pcb-cache-post", OBJECT, "post");
if ($existing) {
  $pid = (int) $existing->ID;
  wp_update_post(array("ID"=>$pid, "comment_status"=>"open", "post_status"=>"publish"));
} else {
  $pid = wp_insert_post(array(
    "post_type" => "post",
    "post_status" => "publish",
    "post_title" => "PCB Cache Post",
    "post_name" => "pcb-cache-post",
    "post_content" => "Cached post body for Super Cache mfunc comments.",
    "comment_status" => "open",
  ), true);
  if (is_wp_error($pid)) { fwrite(STDERR, $pid->get_error_message()); exit(1); }
}
update_option("pcb_post_id", (int) $pid);
echo "pcb_post_id=".$pid."\n";
' --allow-root

# Env-only: disable flood so seed then residual can post in one trial without
# waiting 15s. Does not touch Super Cache / mfunc / phase2.
mkdir -p wp-content/mu-plugins
cat > wp-content/mu-plugins/pcb-comment-env.php <<'PHP'
<?php
/* PatchClosure-Bench env (NOT Super Cache): allow rapid guest comments in one trial. */
add_filter('comment_flood_filter', '__return_false', 99);
add_filter('pre_comment_approved', function ($a) { return 1; }, 99);
PHP

mkdir -p wp-content/cache
chown -R www-data:www-data /var/www/html
touch /flag/ready
echo "[pcb] WP Super Cache ${WPSC_VERSION} ready on ${WPADDR}"
exec apache2-foreground
