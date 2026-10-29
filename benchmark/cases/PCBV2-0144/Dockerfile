# Faithful-core image for the npm `minimist` CLI arg-parser prototype-pollution guard
# (pre-guard 1.2.1  ->  __proto__ string guard 1.2.5 [CVE-2020-7598 fix]  ->  isConstructorOrProto 1.2.6 [CVE-2021-44906 fix]).
# One image, one role selected by HARNESS_VER: an HTTP endpoint whose prototype-pollution guard is the
# REAL, per-version published minimist() setKey(), in front of a benign default-deny flag-gate it protects.
# node:20-slim; the three published minimist versions are installed side-by-side via npm aliases
# (package.json), so the harness invokes the exact published bytes of minimist@1.2.1 (V0), @1.2.5 (V1)
# and @1.2.6 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
