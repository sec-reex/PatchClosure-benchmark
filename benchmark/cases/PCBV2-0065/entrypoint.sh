#!/bin/sh
# One container per profile (v0|v1|v2). Two processes share the container's loopback:
#   1. sidecar  -> holds ${PCB_FLAG}, binds 0.0.0.0:80 (reachable via 127.0.0.1 AND via 0.0.0.0)
#   2. service  -> the REAL axum + activitypub-federation fetch service on :${APP_PORT}
# The service is started with PCB_FLAG STRIPPED from its env, so the flag can only surface in a
# /fetch response via a genuine loopback SSRF that the crate's guard failed to block.
#
# Attack domains resolve via /etc/hosts (== the crate's tokio lookup_host AND reqwest's getaddrinfo):
#   original-target.pcb  -> 127.0.0.1      (seed, CVE-2025-25194: V1 blocks is_loopback; V0 no guard)
#   residual-target.pcb  -> 0.0.0.0        (residual, CVE-2026-33693: V1 omits is_unspecified -> passes;
#                                           OS routes 0.0.0.0 -> localhost -> sidecar; V2 blocks)
#   residual6-target.pcb -> ::ffff:0.0.0.0 (secondary residual, same gap via to_ipv4_mapped)
set -e

echo "127.0.0.1       original-target.pcb"  >> /etc/hosts
echo "0.0.0.0         residual-target.pcb"  >> /etc/hosts
echo "::ffff:0.0.0.0  residual6-target.pcb" >> /etc/hosts

SIDE_PORT=80 PCB_FLAG="${PCB_FLAG}" /usr/local/bin/sidecar &
sleep 0.4

exec env -u PCB_FLAG \
    AP_VER="${AP_VER}" \
    APP_PORT="${APP_PORT:-8080}" \
    INSTANCE_DOMAIN="${INSTANCE_DOMAIN:-svc.pcb}" \
    /usr/local/bin/service
