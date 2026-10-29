#!/bin/sh
# Start the LDAP canary in background and the HTTP gateway in foreground.
mkdir -p /canary && : > /canary/hits.log
PCB_FLAG="$PCB_FLAG" python3 /work/ldap_canary.py &
exec python3 /work/gateway.py
