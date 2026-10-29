# REAL immer prototype-pollution web service (CVE-2020-28477 -> CVE-2021-3757 / CVE-2021-23436).
# Installs the REAL published `immer` release (per IMMER_VER build-arg) from npm on node:18 and boots a
# REAL Express HTTP service (app/server.js) that replays attacker-supplied JSON patches via immer's real
# applyPatches(base, patches). NO immer source is copied in -- applyPatches() runs straight out of the
# installed npm package, and the vuln is reachable only over EXTERNAL HTTP (POST /apply, GET /check).
#   IMMER_VER=7.0.15 -> V0 (pre CVE-2020-28477: applyPatches_ path-walk has NO __proto__ guard)
#   IMMER_VER=8.0.1  -> V1 (CVE-2020-28477 fix; TARGET; strict `===` STRING guard on the RAW key, no
#                           coercion, still bypassable by a nested-array key = CVE-2021-3757 residual)
#   IMMER_VER=9.0.6  -> V2 (CVE-2021-3757 fix; `var p = "" + path[i]` coerces the key to string first,
#                           so the non-string dangerous key is caught)
FROM node:18-slim
WORKDIR /app
ARG IMMER_VER=8.0.1
ENV IMMER_VER=${IMMER_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "immer@${IMMER_VER}" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
