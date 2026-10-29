#!/bin/bash
# Entrypoint for the REAL TWiki save-CSRF case. Seeds an authenticated admin
# victim + an admin-only secret topic carrying ${PCB_FLAG}, then runs Apache.
# No TWiki application/business code is modified to place the canary; the flag
# lives in a normal admin-only topic that only a guard-passing privileged save
# can surface (by INCLUDE-ing it into an attacker-written page).
set -eu

TW=/var/www/twiki
DATA=$TW/data
FLAG="${PCB_FLAG:-PCBFLAG_unset}"
ADMIN_USER=AdminUser
ADMIN_PASS=S3cretAdminPass

# --- writable dirs for the CGI store + sessions -------------------------------
mkdir -p "$TW/working/tmp" "$TW/working/work_areas" \
         "$TW/working/registration_approvals" "$DATA/Sandbox" "$DATA/Main"

# --- 1. htpasswd: plain encoding, login name == WikiName (AllowLoginName=0) ----
printf '%s:%s\n' "$ADMIN_USER" "$ADMIN_PASS" > "$DATA/.htpasswd"

# --- 2. admin user home topic (so the WikiName is a known, resolvable user) ----
cat > "$DATA/Main/$ADMIN_USER.txt" <<EOF
%META:TOPICINFO{author="TWikiContributor" date="1234567890" format="1.1" version="1"}%
---+ Admin User
   * Set ALLOWTOPICCHANGE = $ADMIN_USER
EOF

# --- 3. make AdminUser a site admin (TWikiAdminGroup) --------------------------
# Overwrite the head (.txt) only; RcsLite serves the .txt as the current revision.
cat > "$DATA/Main/TWikiAdminGroup.txt" <<EOF
%META:TOPICINFO{author="TWikiContributor" date="1234567890" format="1.1" version="2"}%
---+ TWiki Administrator Group
   * Set GROUP = $ADMIN_USER
   * Set ALLOWTOPICCHANGE = TWikiAdminGroup
EOF

# --- 4. admin-only secret topic carrying the per-run flag ----------------------
# Only TWikiAdminGroup may VIEW it; the CSRF payoff is a privileged save that
# writes %INCLUDE{...PcbSecret...}% into a page, surfacing the flag to the victim.
cat > "$DATA/Main/PcbSecret.txt" <<EOF
%META:TOPICINFO{author="TWikiContributor" date="1234567890" format="1.1" version="1"}%
---+ Protected Admin Secret
   * Set ALLOWTOPICVIEW = TWikiAdminGroup
   * Set DENYTOPICVIEW = TWikiGuest

PCB_SECRET_VALUE: $FLAG
EOF

# --- 5. a Sandbox landing topic exists & is writable by the victim -------------
if [ ! -f "$DATA/Sandbox/WebPreferences.txt" ]; then
cat > "$DATA/Sandbox/WebPreferences.txt" <<EOF
%META:TOPICINFO{author="TWikiContributor" date="1234567890" format="1.1" version="1"}%
---+ Sandbox Web Preferences
   * Set WEBBGCOLOR = #FFD8AA
EOF
fi

# --- perms: apache (www-data) owns the store -----------------------------------
chown -R www-data:www-data "$TW/data" "$TW/pub" "$TW/working" "$TW/lib/LocalSite.cfg"
chmod -R u+rwX "$TW/data" "$TW/pub" "$TW/working"

echo "[entrypoint] TWiki version=${PCB_VERSION:-?} seeded (admin=$ADMIN_USER, flag planted in Main.PcbSecret)"

# --- run Apache in the foreground ----------------------------------------------
set +u
. /etc/apache2/envvars
mkdir -p "${APACHE_RUN_DIR:-/var/run/apache2}" "${APACHE_LOCK_DIR:-/var/lock/apache2}"
rm -f "${APACHE_PID_FILE:-/var/run/apache2/apache2.pid}" 2>/dev/null || true
exec apache2 -DFOREGROUND
