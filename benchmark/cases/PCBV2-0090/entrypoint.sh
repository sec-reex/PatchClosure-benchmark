#!/bin/sh
# Point the container's resolver DIRECTLY at the rebinding DNS sidecar (bypass Docker's embedded
# 127.0.0.11 cache so the TOCTOU flip is observed on every lookup). Both PHP gethostbyname (the
# CVE-2025-68437 CHECK) and libcurl (the Guzzle FETCH) read /etc/resolv.conf.
echo "nameserver ${DNS_SIDECAR_IP:-192.0.0.53}" > /etc/resolv.conf
echo "options ndots:0 timeout:2 attempts:1" >> /etc/resolv.conf
exec php -S 0.0.0.0:80 /app/harness.php
