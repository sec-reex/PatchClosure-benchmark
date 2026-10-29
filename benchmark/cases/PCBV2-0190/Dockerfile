# Faithful-core image for the npm `set-value` prototype-pollution guard
# (CVE-2019-10747 -> CVE-2021-23440). One image, one role selected by HARNESS_VER: an HTTP endpoint
# whose prototype-pollution guard is the REAL, per-version `set-value`, in front of a benign
# default-deny flag-gate the guard is meant to protect. node:20-slim; the three published set-value
# versions are installed side-by-side via npm aliases (see package.json), so the harness invokes the
# exact published bytes of set-value@3.0.0 (V0), @4.0.0 (V1) and @4.0.1 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
