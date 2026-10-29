# PatchClosure-Bench recipe for fastify-static-cve-2026-15074.
# Runs the REAL @fastify/static npm package (pinned per profile) inside a real
# Fastify server. The static root is /data/root; a canary file planted by the
# entrypoint sits under secret/ outside the guard route.
FROM node:20-slim

ARG FFS_VERSION
ARG FASTIFY_VERSION
WORKDIR /srv
COPY package.json ./
RUN sed -i "s/__VERSION__/${FFS_VERSION}/; s/__FASTIFY_VERSION__/${FASTIFY_VERSION}/" package.json \
 && npm install --no-audit --no-fund

COPY app.js ./

EXPOSE 3000
CMD ["node", "app.js"]
