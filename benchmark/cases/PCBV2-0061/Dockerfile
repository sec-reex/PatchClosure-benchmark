# PatchClosure-Bench: real @keystone-6/core app, one image per version.
# ROUND8 2b slimming: multi-stage — typescript toolchain installs in a throwaway
# builder stage; the runtime image keeps only node_modules + prisma engine.
FROM node:20-bookworm-slim AS builder

ARG KS_VERSION
ENV KS_VERSION=${KS_VERSION}
ENV NODE_ENV=development
# allow prisma postinstall to fetch the schema-engine binary into node_modules
ENV PRISMA_SKIP_POSTINSTALL_GENERATE=0

WORKDIR /build
COPY app/package.json ./package.json
RUN npm install --no-audit --no-fund "@keystone-6/core@${KS_VERSION}" typescript@5 \
 && npm cache clean --force \
 && rm -rf /root/.npm

FROM node:20-bookworm-slim

ENV NODE_ENV=development
ENV PRISMA_SKIP_POSTINSTALL_GENERATE=0

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/node_modules ./node_modules
RUN npx prisma --version >/dev/null 2>&1 || true
COPY app/keystone.ts app/schema.ts app/tsconfig.json ./
COPY app/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
 && mkdir -p /data

EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
