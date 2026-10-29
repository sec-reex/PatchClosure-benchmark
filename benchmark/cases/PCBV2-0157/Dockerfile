# Faithful-core image for the npm `object-path` deep-set prototype-pollution guard
# (pre-guard 0.11.4  ->  string-only `=== '__proto__'` guard 0.11.5 [CVE-2020-15256 fix]  ->  type-coercion 0.11.6 [CVE-2021-23434 fix]).
# One image, one role selected by HARNESS_VER: an HTTP endpoint whose prototype-pollution guard is the
# REAL, per-version published objectPath.withInheritedProps.set(), in front of a benign default-deny flag-gate.
# node:18-slim; the three published object-path versions are installed side-by-side via npm aliases
# (package.json), so the harness invokes the exact published bytes of object-path@0.11.4 (V0),
# @0.11.5 (V1) and @0.11.6 (V2).
FROM node:18-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
