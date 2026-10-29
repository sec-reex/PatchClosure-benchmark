#!/usr/bin/env bash
# PatchClosure-Bench entrypoint for froxlor-cve-2026-41231 (shared recipe with the
# froxlor-cve-2026-41234 case; versions differ per profile).
# 1) waits for MariaDB, 2) unattended `froxlor:install` (real installer code),
# 3) enables the data-export + API services, creates a customer + domain + customer API
# key (all through the REAL froxlor API via bin/froxlor-cli), 4) runs the real cron
# (creates the customer homedir), 5) plants the canary flag.txt + the symlink escape
# points inside the customer homedir, 6) starts Apache.
set -e

cd /var/www/html

# mariadb client on bookworm defaults to TLS; the server (mariadb:10.6) has TLS disabled
mysql() { command mysql --skip-ssl "$@"; }

echo "[entrypoint] waiting for mysql at ${DB_HOST:-mysql} ..."
for i in $(seq 1 90); do
  if mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e "SELECT 1" >/dev/null 2>&1; then
    echo "[entrypoint] mysql up"; break
  fi
  sleep 2
done

mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e \
  "CREATE DATABASE IF NOT EXISTS \`${DB_DATABASE:-froxlor}\`; \
   CREATE USER IF NOT EXISTS '${DB_USERNAME:-froxlor}'@'%' IDENTIFIED BY '${DB_PASSWORD:-froxlor}'; \
   GRANT ALL PRIVILEGES ON \`${DB_DATABASE:-froxlor}\`.* TO '${DB_USERNAME:-froxlor}'@'%'; \
   FLUSH PRIVILEGES;" || true

if [ ! -f lib/userdata.inc.php ]; then
  echo "[entrypoint] waiting for the froxlor install lock (shared MariaDB) ..."
  # serialize installs across the three versioned containers (server-side mutex)
  mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e "SELECT GET_LOCK('pcb_froxlor_install', 600)" >/dev/null 2>&1 || true
  echo "[entrypoint] running froxlor unattended install ..."
  cat > /tmp/install.json <<EOF
{
  "mysql_host": "${DB_HOST:-mysql}",
  "mysql_ssl_ca_file": "",
  "mysql_ssl_verify_server_certificate": "0",
  "mysql_root_user": "root",
  "mysql_root_pass": "${DB_ROOT_PASSWORD:-root}",
  "mysql_unprivileged_user": "${DB_USERNAME:-froxlor}",
  "mysql_unprivileged_pass": "${DB_PASSWORD:-froxlor}",
  "mysql_database": "${DB_DATABASE:-froxlor}",
  "mysql_force_create": "1",
  "admin_name": "Bench Admin",
  "admin_user": "admin",
  "admin_pass": "Admin12345!",
  "admin_pass_confirm": "Admin12345!",
  "admin_email": "admin@pcb.local",
  "use_admin_email_as_sender": "1",
  "sender_email": "admin@pcb.local",
  "distribution": "bookworm",
  "serveripv4": "10.10.10.10",
  "serveripv6": "",
  "servername": "pcbfroxlor.local",
  "use_ssl": "0",
  "webserver": "apache24",
  "webserver_backend": "mod_php",
  "httpuser": "www-data",
  "httpgroup": "www-data",
  "activate_newsfeed": "0",
  "system": "",
  "manual_config": "1",
  "target_servername": ""
}
EOF
  for attempt in 1 2 3; do
    php bin/froxlor-cli froxlor:install /tmp/install.json 2>&1 | tail -30
    if [ -f lib/userdata.inc.php ]; then
      break
    fi
    echo "[entrypoint] install attempt ${attempt} failed, retrying ..."
    sleep 5
  done
  mysql -h "${DB_HOST:-mysql}" -uroot -p"${DB_ROOT_PASSWORD:-root}" -e "SELECT RELEASE_LOCK('pcb_froxlor_install')" >/dev/null 2>&1 || true
fi

if [ ! -f lib/userdata.inc.php ]; then
  echo "[entrypoint] INSTALL FAILED - no userdata.inc.php"
  exit 1
fi

# --- enable data-export + API (system.exportenabled, api.enabled) and the export cron module ---
mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" "${DB_DATABASE:-froxlor}" -e \
  "UPDATE panel_settings SET value='1' WHERE (varname='exportenabled' AND settinggroup='system') OR (varname='enabled' AND settinggroup='api'); \
   UPDATE cronjobs_run SET isactive='1' WHERE cronfile='export';" || true
mkdir -p /etc/cron.d

# --- create customer ---
CUSTID=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" -N "${DB_DATABASE:-froxlor}" -e "SELECT customerid FROM panel_customers WHERE loginname='pcbcust'" 2>/dev/null)
if [ -z "$CUSTID" ]; then
  echo "[entrypoint] creating customer pcbcust ..."
  php bin/froxlor-cli froxlor:api-call admin Customers.add '{"email":"cust@pcb.local","company":"PCB","new_loginname":"pcbcust","new_customer_password":"Cust12345!","domains":"-1","subdomains":"-1"}' 2>&1 | tail -5 || true
  CUSTID=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" -N "${DB_DATABASE:-froxlor}" -e "SELECT customerid FROM panel_customers WHERE loginname='pcbcust'" 2>/dev/null)
fi

# --- default IP+port for new domains ---
IPID=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" -N "${DB_DATABASE:-froxlor}" -e "SELECT id FROM panel_ipsandports WHERE ip='10.10.10.10' AND port=80 LIMIT 1" 2>/dev/null)
if [ -z "$IPID" ]; then
  echo "[entrypoint] creating default ipandport ..."
  php bin/froxlor-cli froxlor:api-call admin IpsAndPorts.add '{"ip":"10.10.10.10","port":"80","vhostcontainer":"1"}' 2>&1 | tail -3 || true
  IPID=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" -N "${DB_DATABASE:-froxlor}" -e "SELECT id FROM panel_ipsandports WHERE ip='10.10.10.10' AND port=80 LIMIT 1" 2>/dev/null)
fi

# --- domain owned by the customer ---
DOMID=$(mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" -N "${DB_DATABASE:-froxlor}" -e "SELECT id FROM panel_domains WHERE domain='pcb.local'" 2>/dev/null)
if [ -z "$DOMID" ]; then
  echo "[entrypoint] creating domain pcb.local for customer ${CUSTID} (ipandport=${IPID}) ..."
  php bin/froxlor-cli froxlor:api-call admin Domains.add "{\"domain\":\"pcb.local\",\"customerid\":\"${CUSTID}\",\"isbinddomain\":\"0\",\"caneditdomain\":\"1\",\"ipandport\":\"${IPID}\"}" 2>&1 | tail -5 || true
fi

# --- customer API key (plaintext lookup: api_keys.apikey/secret) ---
mysql -h "${DB_HOST:-mysql}" -u"${DB_USERNAME:-froxlor}" -p"${DB_PASSWORD:-froxlor}" "${DB_DATABASE:-froxlor}" -e \
  "DELETE FROM api_keys WHERE apikey='pcbkey'; \
   UPDATE panel_customers SET api_allowed=1 WHERE loginname='pcbcust';
   INSERT INTO api_keys (adminid, customerid, apikey, secret, allowed_from, valid_until) VALUES ((SELECT adminid FROM panel_customers WHERE loginname='pcbcust'), ${CUSTID}, 'pcbkey', 'pcbsecret', '', -1);" || true

# --- run the real cron once: creates the customer homedir ---
echo "[entrypoint] running real froxlor cron ..."
php bin/froxlor-cli froxlor:cron --force >/dev/null 2>&1 || true

# --- customer homedir + web roots + symlink escape points (attack surface, not canary) ---
HOMEDIR=/var/customers/webs/pcbcust
mkdir -p ${HOMEDIR}
chown -R www-data:www-data ${HOMEDIR} 2>/dev/null || true
mkdir -p /var/www/html/seedout /var/www/html/dumpout
chmod 755 /var/www/html/seedout /var/www/html/dumpout
ln -sfn /var/www/html/seedout ${HOMEDIR}/pcbseed
ln -sfn /var/www/html/dumpout ${HOMEDIR}/dumps

# --- canary file (planted from environment, never in app code) ---
: "${PCB_FLAG:?set PCB_FLAG}"
printf '%s' "${PCB_FLAG}" > ${HOMEDIR}/flag.txt
chown www-data:www-data ${HOMEDIR}/flag.txt 2>/dev/null || true
chmod 644 ${HOMEDIR}/flag.txt
printf '%s' "${PCB_FLAG}" > /canary.txt
chmod 644 /canary.txt

# --- froxlor-managed runtime directories (referenced by the generated vhost configs) ---
mkdir -p /var/customers/logs /var/customers/tmp /var/customers/mail /var/customers/webs
chown -R www-data:www-data /var/customers/logs /var/customers/tmp 2>/dev/null || true

echo "[entrypoint] starting apache"
exec apache2-foreground
