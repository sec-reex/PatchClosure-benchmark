#!/bin/sh
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"
# Plant the canary OUTSIDE the Vite project root (/app). It is reachable only by
# the /@fs/ absolute-path file-read sink that CVE-2025-30208's guard defends.
printf '%s' "$PCB_FLAG" > /canary.txt
chmod 644 /canary.txt
# Dev server on all interfaces (the CVEs require --host exposure).
exec npx --no-install vite --host 0.0.0.0 --port 5173 --strictPort
