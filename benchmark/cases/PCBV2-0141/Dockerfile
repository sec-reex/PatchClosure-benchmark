# Faithful-core image for the npm `lodash` _.merge (baseMergeDeep/safeGet) prototype-pollution guard
# (CVE-2018-3721 -> CVE-2018-16487). One image, one role selected by HARNESS_VER: an HTTP endpoint whose
# prototype-pollution guard is the REAL, per-version `lodash` merge machinery, in front of a benign
# default-deny flag-gate the guard is meant to protect. node:20-slim; the three published lodash versions
# are installed side-by-side via npm aliases (see package.json), so the harness invokes the exact published
# bytes of lodash@4.17.4 (V0), @4.17.5 (V1) and @4.17.11 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
