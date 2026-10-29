# Faithful-core image for the npm `locutus` parse_str prototype-pollution guard
# (CVE-2026-25521 -> CVE-2026-33994). One image, one role selected by HARNESS_VER: an HTTP
# endpoint whose prototype-pollution guard is the REAL, per-version `locutus` parse_str, plus a
# benign flag-gate the guard is meant to protect. node:20-slim; the three published locutus
# versions are installed side-by-side via npm aliases (see package.json), so the harness invokes
# the exact published bytes of locutus@2.0.38 (V0), @2.0.39 (V1) and @3.0.25 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
