#!/bin/sh
# Point the container's resolver DIRECTLY at the static DNS sidecar (bypass Docker's embedded
# 127.0.0.11 cache) so both PHP gethostbyname (the CVE-2025-68437 IPv4-only CHECK) and libcurl
# (the Guzzle FETCH, which resolves AAAA via getaddrinfo) read our zones for pcb.test.
echo "nameserver ${DNS_SIDECAR_IP:-192.0.0.53}" > /etc/resolv.conf
echo "options ndots:0 timeout:2 attempts:1" >> /etc/resolv.conf
exec php -S 0.0.0.0:80 /app/harness.php
