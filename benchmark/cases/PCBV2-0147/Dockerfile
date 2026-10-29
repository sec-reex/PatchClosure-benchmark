# Faithful-core image for the Mongoose populate().match $where search-injection guard
# (CVE-2024-53900 -> CVE-2025-23061). One image, one role selected by HARNESS_VER: an HTTP
# service whose populate-match sanitizer is the REAL, per-version npm `mongoose` package. The
# three `mongoose` versions are installed side-by-side via npm aliases (see package.json), so the
# harness imports the exact published bytes of mongoose@8.8.2 (V0), 8.8.3 (V1), 8.9.5 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
