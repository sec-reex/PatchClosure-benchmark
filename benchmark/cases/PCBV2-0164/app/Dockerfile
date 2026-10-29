# Official parseplatform/parse-server has no 6.4.0 / 6.5.0 tags.
# Pin the exact npm release on an official node image.
FROM node:18-bookworm-slim
WORKDIR /app
ARG PARSE_VER=6.5.0
ENV PARSE_VER=${PARSE_VER}
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund parse-server@${PARSE_VER} express@4
COPY server.js /app/server.js
EXPOSE 1337
CMD ["node", "server.js"]
