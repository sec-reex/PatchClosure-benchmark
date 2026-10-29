# Faithful-core image for the npm `lodash` _.unset (baseUnset) prototype-pollution guard
# (CVE-2025-13465 -> CVE-2026-2950). One image, one role selected by HARNESS_VER: an HTTP endpoint
# whose prototype-pollution guard is the REAL, per-version `lodash` baseUnset, in front of a benign
# default-deny flag-gate the guard is meant to protect. node:20-slim; the three published lodash
# versions are installed side-by-side via npm aliases (see package.json), so the harness invokes the
# exact published bytes of lodash@4.17.21 (V0), @4.17.23 (V1) and @4.18.1 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
