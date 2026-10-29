# PatchClosure-Bench recipe for fastify-static-cve-2026-7120.
# Runs the REAL @fastify/static npm package (pinned per profile) inside a real
# Fastify server with an allowedPath security boundary over /private/.
FROM node:20-slim

ARG FFS_VERSION
WORKDIR /srv
COPY package.json ./
RUN sed -i "s/__VERSION__/${FFS_VERSION}/" package.json \
 && npm install --no-audit --no-fund

COPY app.js ./

EXPOSE 3000
CMD ["node", "app.js"]
