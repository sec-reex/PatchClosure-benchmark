FROM node:20-slim
ARG FR_VERSION
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 && npm i follow-redirects@${FR_VERSION} >/dev/null 2>&1
# record the resolved version for provenance
RUN node -e "console.log('follow-redirects', require('follow-redirects/package.json').version)"
COPY probe.mjs /app/probe.mjs
COPY gateway.mjs /app/gateway.mjs
CMD ["node", "/app/gateway.mjs"]
