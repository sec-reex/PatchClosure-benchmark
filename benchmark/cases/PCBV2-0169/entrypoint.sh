#!/bin/sh
# Plant the per-run benign canary in the ENVIRONMENT (never in PHPMailer's official code).
# ${PCB_FLAG} is written to /canary/flag.txt; the injected sendmail `-X<path>` arg (see
# sendmail_shim.sh) is what copies it to the attacker-chosen path, which the harness reads back.
set -e
: "${PCB_FLAG:?PCB_FLAG must be set to the per-run canary token}"
mkdir -p /canary
printf '%s' "${PCB_FLAG}" > /canary/flag.txt
chmod 0644 /canary/flag.txt
rm -f /canary/out.txt /canary/argv.log
exec php -d error_reporting=0 -S 0.0.0.0:8080 /opt/harness.php
