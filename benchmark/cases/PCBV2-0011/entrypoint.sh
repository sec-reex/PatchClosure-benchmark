#!/bin/sh
# Plant the per-run canary OUTSIDE the docroot (/var/www/html). A normal HTTP GET can never read
# /flag/pcb_flag.txt; only an executed '#'-render-array callable (the code-execution this
# RequestSanitizer guard defends against) can surface it -> genuine differential signal.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
mkdir -p /flag
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt
# Hand off to the official Drupal image entrypoint (docker-php-entrypoint) + apache2-foreground.
exec /usr/local/bin/docker-php-entrypoint "$@"
