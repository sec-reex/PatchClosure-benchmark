#!/bin/sh
# Plant the per-run canary OUTSIDE the docroot. A normal HTTP GET can never read it; only PHP
# that the WP Super Cache mfunc sink emits into an executed cache file (the code injection this
# comment filter defends against) can echo it.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
mkdir -p /flag
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt
exec "$@"
