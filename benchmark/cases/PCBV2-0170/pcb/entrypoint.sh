#!/bin/bash
# Entrypoint for a real phpMyFAQ per-version container.
#   1. wait for MariaDB
#   2. start Apache (mod_php)
#   3. if not yet installed, POST the REAL web installer (setup/index.php/install) over HTTP
#   4. seed the low-privilege 'editor' user + the api.apiClientToken=${PCB_FLAG} canary
set -u

: "${PMF_DB_HOST:=db}"
: "${PMF_DB_NAME:=pmf}"
: "${PMF_DB_USER:=pmf}"
: "${PMF_DB_PASS:=pmfpass}"
: "${PMF_ADMIN_PW:=AdminPass12345}"
: "${PMF_EDITOR_PW:=EditorPass12345}"

DOCROOT=/opt/phpmyfaq-src/phpmyfaq
DBFILE="${DOCROOT}/content/core/config/database.php"

echo "[entrypoint] waiting for MariaDB at ${PMF_DB_HOST} ..."
for i in $(seq 1 60); do
  if mysqladmin ping -h"${PMF_DB_HOST}" -u"${PMF_DB_USER}" -p"${PMF_DB_PASS}" --silent 2>/dev/null; then
    echo "[entrypoint] MariaDB is up"; break
  fi
  sleep 2
done

echo "[entrypoint] starting Apache ..."
apache2-foreground &
APACHE_PID=$!

echo "[entrypoint] waiting for Apache ..."
for i in $(seq 1 60); do
  if curl -s -o /dev/null "http://localhost/setup/index.php"; then break; fi
  sleep 1
done

if [ ! -f "${DBFILE}" ]; then
  echo "[entrypoint] running REAL phpMyFAQ web installer for tag ${PMF_TAG} ..."
  OUT=$(curl -sS -X POST "http://localhost/setup/index.php/install" \
    --data-urlencode "sqltblpre=" \
    --data-urlencode "sql_type=mysqli" \
    --data-urlencode "sql_server=${PMF_DB_HOST}" \
    --data-urlencode "sql_port=3306" \
    --data-urlencode "sql_user=${PMF_DB_USER}" \
    --data-urlencode "sql_password=${PMF_DB_PASS}" \
    --data-urlencode "sql_db=${PMF_DB_NAME}" \
    --data-urlencode "loginname=admin" \
    --data-urlencode "password=${PMF_ADMIN_PW}" \
    --data-urlencode "password_retyped=${PMF_ADMIN_PW}" \
    --data-urlencode "language=en" \
    --data-urlencode "realname=Super Admin" \
    --data-urlencode "email=admin@example.test" \
    --data-urlencode "permLevel=basic")
  echo "[entrypoint] installer response (trimmed):"
  echo "${OUT}" | grep -iE 'error|installation|success' | head -20
  if [ -f "${DBFILE}" ]; then
    echo "[entrypoint] install OK (database.php written). Seeding editor + flag ..."
    php /opt/pcb_seed.php
  else
    echo "[entrypoint] INSTALL FAILED: database.php not written. Full response:"; echo "${OUT}"
  fi
else
  echo "[entrypoint] already installed; skipping."
fi

wait "${APACHE_PID}"
