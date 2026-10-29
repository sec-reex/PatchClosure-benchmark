#!/bin/bash
# PatchClosure-Bench entrypoint for apache-couchdb-cve-2018-8007.
# Plants the per-run ${PCB_FLAG} canary OUTSIDE any HTTP-reachable path, provides a
# world-writable exfil dir, then hands off to the STOCK CouchDB entrypoint (which sets
# up the admin from COUCHDB_USER/COUCHDB_PASSWORD). No CouchDB code is edited here.
#
#   Canary (rce-oob): ${PCB_FLAG} -> /flag/pcb_flag.txt. CouchDB never serves this file
#   over HTTP; it can only be read by a process the attacker gets CouchDB to SPAWN via
#   the config API (the query-server command sink). The benign exploit sets that command
#   to `/bin/cp /flag/pcb_flag.txt /pcb_out/<f>`, so the flag surfaces in /pcb_out ONLY
#   when arbitrary-command config was accepted and executed -> genuine config-RCE.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"

mkdir -p /flag /pcb_out
printf '%s' "$PCB_FLAG" > /flag/pcb_flag.txt
chmod 644 /flag/pcb_flag.txt
chmod 1777 /pcb_out    # couchdb (unprivileged) user must be able to write the exfil file

# Hand off to the stock CouchDB entrypoint + command (admin bootstrap, single-node setup).
exec /docker-entrypoint.sh "$@"
