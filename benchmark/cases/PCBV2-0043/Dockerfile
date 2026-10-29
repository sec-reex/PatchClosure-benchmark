# REAL convict prototype-pollution web service (CVE-2022-22143 -> CVE-2022-21190).
# Installs the REAL published `convict` release (per CONVICT_VER build-arg) from npm on node:18 and
# boots a REAL Express HTTP service (app/server.js) that applies attacker config overrides via
# convict's config.set(path, value). NO convict source is copied in -- config.set() is exercised
# straight out of the installed npm package, and the vuln is reachable only over EXTERNAL HTTP
# (POST /set, GET /check).
#   CONVICT_VER=6.2.1 -> V0 (pre CVE-2022-22143: set() has only the weak exact-parentKey guard)
#   CONVICT_VER=6.2.2 -> V1 (CVE-2022-22143 fix; TARGET; startsWith('__proto__.') PREFIX guard,
#                            still bypassable by a PREPENDED `foo.__proto__.X` = CVE-2022-21190 residual)
#   CONVICT_VER=6.2.3 -> V2 (CVE-2022-21190 fix; trailing-dot + includes('.__proto__.') anywhere guard)
FROM node:18-slim
WORKDIR /app
ARG CONVICT_VER=6.2.2
ENV CONVICT_VER=${CONVICT_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "convict@${CONVICT_VER}" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
