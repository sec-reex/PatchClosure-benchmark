# Faithful-core image for the npm `dottie` Dottie.set prototype-pollution guard
# (CVE-2023-26132 -> CVE-2026-27837). One image, one role selected by HARNESS_VER: an HTTP endpoint
# whose prototype-pollution guard is the REAL, per-version `dottie` Dottie.set, in front of a benign
# default-deny flag-gate the guard is meant to protect. node:20-slim; the three published dottie
# versions are installed side-by-side via npm aliases (see package.json), so the harness invokes the
# exact published bytes of dottie@2.0.3 (V0), @2.0.4 (V1) and @2.0.7 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
