# Recipe-based (no committed node_modules / images). The official Node base is
# pulled and @angular/ssr@${SSR_VERSION} + pinned Angular peers are installed at
# BUILD time. Only the tiny host sources (server.mjs, app-server-entry.mjs) are
# copied in.
FROM node:20-bookworm-slim

WORKDIR /app
COPY package.json server.mjs app-server-entry.mjs ./

# Pin the vulnerable/target @angular/ssr version per compose profile.
ARG SSR_VERSION=20.3.17
# Angular runtime peers pinned for deterministic builds (same set works for
# ssr 20.3.16 / 20.3.17 / 20.3.21).
ARG NG_VERSION=20.3.6

RUN npm install --no-audit --no-fund --loglevel=error \
      @angular/ssr@${SSR_VERSION} \
      @angular/core@${NG_VERSION} \
      @angular/common@${NG_VERSION} \
      @angular/compiler@${NG_VERSION} \
      @angular/platform-server@${NG_VERSION} \
      @angular/platform-browser@${NG_VERSION} \
      @angular/router@${NG_VERSION} \
      rxjs@7.8.2 zone.js@0.15.1 \
 && npm cache clean --force

ENV PORT=8080
ENV NG_ALLOWED_HOSTS=127.0.0.1,localhost
EXPOSE 8080
