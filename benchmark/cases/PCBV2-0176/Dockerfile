# REAL json-ptr prototype-pollution web service (CVE-2020-7766 -> CVE-2021-23509).
# Installs the REAL published `json-ptr` release (per JSONPTR_VER build-arg) from npm on node:18 and
# boots a REAL Express HTTP service (app/server.js) that sets attacker JSON by pointer via json-ptr's
# static JsonPointer.set(target, pointer, value, force). NO json-ptr source is copied in -- set() is
# exercised straight out of the installed npm package, and the vuln is reachable only over EXTERNAL
# HTTP (POST /set, GET /check).
#   JSONPTR_VER=1.3.0 -> V0 (pre CVE-2020-7766: setValueAtPath segment-walk has NO __proto__ guard)
#   JSONPTR_VER=2.0.0 -> V1 (CVE-2020-7766 fix; TARGET; string-only `step === '__proto__'` guard, still
#                            bypassable by a nested-array segment = CVE-2021-23509 residual)
#   JSONPTR_VER=3.0.0 -> V2 (CVE-2021-23509 fix; per-segment `typeof step` type-check rejects it first)
FROM node:18-slim
WORKDIR /app
ARG JSONPTR_VER=2.0.0
ENV JSONPTR_VER=${JSONPTR_VER}
# NOTE: json-ptr@1.3.0 ships compiled code that `require('tslib')` but forgot to DECLARE it as a
# dependency (packaging bug), so tslib is installed explicitly. json-ptr@2.0.0 declares tslib@^2.0.3
# itself; @3.0.0 needs none -- the explicit tslib is harmless/consistent across all three.
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "json-ptr@${JSONPTR_VER}" "tslib@2" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
