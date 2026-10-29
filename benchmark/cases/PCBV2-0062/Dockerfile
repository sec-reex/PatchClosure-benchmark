# Faithful-core image for the npm `dset` deep-set prototype-pollution guard
# (pre-guard 2.0.1  ->  string-only guard 3.1.2 [CVE-2022-25645 fixed release]  ->  string-coercion 3.1.4 [CVE-2024-21529 fix]).
# One image, one role selected by HARNESS_VER: an HTTP endpoint whose prototype-pollution guard is the
# REAL, per-version published `dset()`, in front of a benign default-deny flag-gate the guard protects.
# node:20-slim; the three published dset versions are installed side-by-side via npm aliases (package.json),
# so the harness invokes the exact published bytes of dset@2.0.1 (V0), @3.1.2 (V1) and @3.1.4 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
