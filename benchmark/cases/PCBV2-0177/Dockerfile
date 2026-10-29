# REAL set-in prototype-pollution web service (CVE-2020-28273 -> CVE-2022-25354).
# Installs the REAL published `set-in` release (per SETIN_VER build-arg) from npm on node:18 and
# boots a REAL Express HTTP service (app/server.js) that merges attacker JSON via set-in. NO set-in
# source is copied in -- setIn() is exercised straight out of the installed npm package, and the
# vuln is reachable only over EXTERNAL HTTP (POST /merge, GET /check).
#   SETIN_VER=2.0.0 -> V0 (pre CVE-2020-28273: setIn key-walk has NO __proto__ guard)
#   SETIN_VER=2.0.1 -> V1 (CVE-2020-28273 fix; TARGET; string-only `!== '__proto__'` assert, still
#                          bypassable by a nested-array key = CVE-2022-25354 residual)
#   SETIN_VER=2.0.3 -> V2 (CVE-2022-25354 fix; entry-level type-check rejects the non-string key)
FROM node:18-slim
WORKDIR /app
ARG SETIN_VER=2.0.1
ENV SETIN_VER=${SETIN_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "set-in@${SETIN_VER}" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
