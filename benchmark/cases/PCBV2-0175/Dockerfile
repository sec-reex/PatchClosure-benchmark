# REAL deep-get-set prototype-pollution web service (CVE-2020-7715 -> CVE-2022-21231).
# Installs the REAL published `deep-get-set` release (per DGS_VER build-arg) from npm on node:18 and
# boots a REAL Express HTTP service (app/server.js) that sets attacker JSON via deep-get-set. NO
# deep-get-set source is copied in -- deep(obj, path, value) is exercised straight out of the installed
# npm package, and the vuln is reachable only over EXTERNAL HTTP (POST /set, GET /check).
#   DGS_VER=1.1.0 -> V0 (pre CVE-2020-7715: set() key-walk has NO magic-property guard)
#   DGS_VER=1.1.1 -> V1 (CVE-2020-7715 fix; TARGET; string-only isSafeKey `!== '__proto__'` guard,
#                        still bypassable by a nested-array key = CVE-2022-21231 residual)
#   DGS_VER=1.1.2 -> V2 (CVE-2022-21231 fix; isUnsafeKey matches the nested-array key first;
#                        dual ESM/CJS package, require() resolves index.cjs)
FROM node:18-slim
WORKDIR /app
ARG DGS_VER=1.1.1
ENV DGS_VER=${DGS_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "deep-get-set@${DGS_VER}" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
