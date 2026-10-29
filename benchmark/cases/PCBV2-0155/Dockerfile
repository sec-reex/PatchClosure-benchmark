# REAL Nuxt + nuxt-og-image SSRF benchmark image
# (GHSA-pqhr-mp3f-hrpp / V1 = 6.2.5 incomplete-fix TARGET -> CVE-2026-44589 / V2 = 6.4.9).
#
# Builds a REAL minimal Nuxt 4 app that enables the REAL published nuxt-og-image
# module (version selected by the OGI_VER build-arg) and boots it in PRODUCTION via
# `node .output/server/index.mjs`. NO module source is lifted -- isBlockedUrl and the
# $fetch(decodedSrc) egress are exercised straight out of the installed module through
# the module's own og-image HTTP endpoint.
#
#   OGI_VER=6.2.4 -> V0 (pre GHSA-pqhr-mp3f-hrpp: no isBlockedUrl)
#   OGI_VER=6.2.5 -> V1 (GHSA-pqhr-mp3f-hrpp fix; TARGET; hex IPv4-mapped loopback residual open)
#   OGI_VER=6.4.9 -> V2 (CVE-2026-44589 fix: full IPv6 expansion + fetchWithRedirectValidation)
#
# Nuxt is pinned to 4.4.5: it satisfies nuxt-og-image's @nuxt/kit ^4.4.2 requirement and
# ships @nuxt/nitro-server 4.4.5, whose island handler renders the OG component (the
# module renders via an internal island request); nitro-server >= 4.4.6 added an island
# hash check that the module's own island hashing does not match. satori is pinned to the
# module's tested ^0.26.0.
FROM node:20-slim
ARG OGI_VER=6.2.5
ENV OGI_VER=${OGI_VER}
WORKDIR /app

# Real app source (text only; no node_modules, no module source).
COPY app/ /app/

# Install the REAL published module + Nuxt, then do a REAL production build.
# Retry + legacy-peer-deps: sweep flakes are registry/peer, not a missing package.
RUN set -eux; \
    n=0; \
    until [ "$n" -ge 3 ]; do \
      npm i --no-audit --no-fund && break; \
      n=$((n+1)); npm i --no-audit --no-fund --legacy-peer-deps && break; \
      sleep 15; \
    done; \
    npm i "nuxt-og-image@${OGI_VER}" --no-audit --no-fund; \
    NITRO_PRESET=node-server npx nuxt build; \
    npm cache clean --force

COPY sidecar.mjs /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
CMD ["/app/entrypoint.sh"]
