# Faithful-core image for the npm `tar-fs` archive-extraction symlink / path-containment guard
# (pre-symlink-guard 3.0.6 -> onsymlink inCwd check 3.0.7 [CVE-2024-12905 fix] -> full-ancestor
#  validate() + directory-entry validation + hardlink realpath 3.0.9 [CVE-2025-48387 fix]).
# One image, one role selected by HARNESS_VER: an HTTP endpoint whose extraction guard is the REAL,
# per-version published tar-fs extract(), in front of a benign default-deny escape-gate.
# node:20-slim; the three published tar-fs versions (3.0.6=V0, 3.0.7=V1, 3.0.9=V2) are installed
# side-by-side via npm aliases (all three are real npm publishes; nothing is reconstructed).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
EXPOSE 8080
