#!/bin/bash
# Wait for MySQL, load NukeSentinel tables + per-run canary, start Apache.
# The official html/ overlay is already in /var/www/html from the image build.
set -euo pipefail

echo "Waiting for MySQL at ${DB_HOST}:3306 ..."
for i in $(seq 1 90); do
  if php -r '$m=@new mysqli(getenv("DB_HOST"),getenv("DB_USER"),getenv("DB_PASS"),getenv("DB_NAME"),3306); if($m && empty($m->connect_error)){exit(0);} exit(1);' 2>/dev/null; then
    echo "MySQL ready."
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    echo "MySQL not ready after 90s" >&2
    exit 1
  fi
  sleep 1
done

php -r '
$m = new mysqli(getenv("DB_HOST"), getenv("DB_USER"), getenv("DB_PASS"), getenv("DB_NAME"), 3306);
if ($m->connect_error) { fwrite(STDERR, "DB connect failed: ".$m->connect_error."\n"); exit(1); }
$m->multi_query(file_get_contents("/opt/init.sql"));
while ($m->next_result()) {;}
$m->query("DELETE FROM pcb_secret");
$flag = getenv("PCB_FLAG");
if ($flag === false || $flag === "") { fwrite(STDERR, "PCB_FLAG empty\n"); exit(1); }
$esc = $m->real_escape_string($flag);
$m->query("INSERT INTO pcb_secret (id, secret) VALUES (1, \"".$esc."\")");
echo "Schema init + flag planted.\n";
$m->close();
'

test -f /var/www/html/includes/nukesentinel.php
echo "Starting Apache with NS_VERSION=${NS_VERSION:-} (real nukesentinel.php from official tarball) ..."
exec apache2-foreground
