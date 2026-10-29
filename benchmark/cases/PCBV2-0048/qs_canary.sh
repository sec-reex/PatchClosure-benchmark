#!/bin/sh
# Benign query-server CANARY (rce-oob). CouchDB spawns whatever command an admin registers
# in [query_servers] as an external "query server". This benign stand-in merely copies the
# planted flag file to the observable exfil path given as $1, then stays alive so CouchDB's
# proc_manager keeps it as an idle process instead of respawn-storming a fast-exiting proc.
# It is NOT a real payload: its only effect is to prove that an arbitrary command placed in
# the (blacklisted) query_servers config was accepted and EXECUTED.
cp /flag/pcb_flag.txt "$1" 2>/dev/null
exec sleep 100000000
