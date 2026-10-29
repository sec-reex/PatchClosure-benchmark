FROM node:20-bullseye-slim

ARG VM2_VERSION=3.10.0
RUN mkdir -p /app && cd /app \
    && npm init -y >/dev/null 2>&1 \
    && npm install vm2@${VM2_VERSION} --no-audit --no-fund >/dev/null 2>&1

COPY server.js /app/server.js

WORKDIR /app
EXPOSE 3000
CMD ["node", "/app/server.js"]
