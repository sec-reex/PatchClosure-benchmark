# PatchClosure-Bench recipe for lodash-cve-2026-4800.
# Runs a real Fastify "template compiler" service using the REAL lodash package
# (pinned per profile). Canary at /canary.txt planted by the entrypoint.
FROM node:20-slim

ARG LODASH_VERSION
WORKDIR /srv
COPY package.json ./
RUN sed -i "s/__VERSION__/${LODASH_VERSION}/" package.json \
 && npm install --no-audit --no-fund

COPY app.js ./

EXPOSE 3000
CMD ["node", "app.js"]
