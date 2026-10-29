#!/bin/sh
# Plant the per-run canary OUTSIDE the docroot. A normal HTTP GET can never read it;
# only a PHP file that gets executed (the RCE this extension filter defends against) can.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
mkdir -p /flag
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt
mkdir -p /var/www/html/uploads
chown -R www-data:www-data /var/www/html/uploads
exec "$@"
