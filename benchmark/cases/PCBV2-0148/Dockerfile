# Faithful-core image for the npm `netmask`-package SSRF/IP-ACL guard
# (CVE-2021-28918 -> CVE-2021-29418). One image, one role selected by HARNESS_VER:
# an HTTP fetcher whose SSRF guard is the REAL, per-version npm `netmask` package
# (Netmask(block).contains(host) over a private-range denylist), plus a loopback-only
# flag sidecar the guard is meant to protect. node:20-slim ships native `fetch` (undici)
# -- the outbound sink -- and the three `netmask` versions are installed side-by-side via
# npm aliases (see package.json), so the harness imports the exact published bytes of
# netmask@1.0.6 (V0), netmask@2.0.0 (V1, the CVE-2021-28918 fix / TARGET) and
# netmask@2.0.1 (V2, the CVE-2021-29418 complete fix).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
