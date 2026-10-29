# REAL Astro server image for the /_image isRemotePath allowlist SSRF case
# (CVE-2025-55303 -> CVE-2025-59837). NOT a source-lift: this installs the REAL published `astro`
# at the version chosen by ASTRO_VER plus the REAL @astrojs/node adapter, and runs `astro build`
# to produce a genuine standalone Node SSR server. The isRemotePath/isRemoteAllowed guard under test
# is pulled in TRANSITIVELY as astro's own @astrojs/internal-helpers dependency:
#   ASTRO_VER=5.13.1  -> internal-helpers 0.7.1  (V0, pre CVE-2025-55303)
#   ASTRO_VER=5.13.4  -> internal-helpers 0.7.2  (V1, CVE-2025-55303 fix / incomplete TARGET)
#   ASTRO_VER=5.13.10 -> internal-helpers 0.7.3  (V2, CVE-2025-59837 complete fix)
# @astrojs/node 9.4.4 (peer astro ^5.7.0) is compatible with all three.
FROM node:20-slim
WORKDIR /app
ARG ASTRO_VER=5.13.4
COPY app/package.json /app/package.json
RUN npm install --no-audit --no-fund astro@${ASTRO_VER} @astrojs/node@9.4.4
COPY app/astro.config.mjs /app/astro.config.mjs
COPY app/src /app/src
RUN npx --no-install astro build
# Record which internal-helpers version astro actually resolves for the endpoint (audit aid).
RUN node -e "const {createRequire}=require('module');const r=createRequire('/app/node_modules/astro/dist/assets/endpoint/generic.js');const p=r.resolve('@astrojs/internal-helpers/path');console.log('astro resolves internal-helpers/path from',p);"
ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080
CMD ["node", "./dist/server/entry.mjs"]
