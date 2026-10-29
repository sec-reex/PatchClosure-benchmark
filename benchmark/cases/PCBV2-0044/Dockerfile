# REAL jsonpointer prototype-pollution web service (CVE-2020-7709 -> CVE-2021-23820/CVE-2022-4742).
# Installs the REAL published `jsonpointer` release (per JSONPOINTER_VER build-arg) from npm on
# node:18 and boots a REAL Express HTTP service (app/server.js) that sets a value into fresh JSON
# state via jsonpointer.set(obj, pointer, value). NO jsonpointer source is copied in -- set() is
# exercised straight out of the installed npm package, and the vuln is reachable only over EXTERNAL
# HTTP (POST /set, GET /check).
#   JSONPOINTER_VER=4.0.1 -> V0 (pre CVE-2020-7709: setter() key-walk has NO __proto__ guard)
#   JSONPOINTER_VER=4.1.0 -> V1 (CVE-2020-7709 fix; TARGET; strict-=== string guard on RAW pointer[1]
#                                only, still bypassable by a nested-array segment = CVE-2021-23820)
#   JSONPOINTER_VER=5.0.0 -> V2 (CVE-2021-23820/CVE-2022-4742 fix; compilePointer() array-element
#                                type-check + per-segment loop guard reject the non-string segment)
FROM node:18-bookworm-slim
WORKDIR /app
ARG JSONPOINTER_VER=4.1.0
ENV JSONPOINTER_VER=${JSONPOINTER_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund "jsonpointer@${JSONPOINTER_VER}" "express@4.21.2"
COPY app/server.js /app/server.js
EXPOSE 8080
CMD ["node", "server.js"]
