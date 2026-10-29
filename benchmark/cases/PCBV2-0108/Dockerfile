FROM node:20-slim
ARG FASTJWT_VERSION
WORKDIR /app
# Pin fast-jwt to the per-profile version + a fixed express.
RUN npm init -y >/dev/null 2>&1 \
    && npm i --no-audit --no-fund fast-jwt@${FASTJWT_VERSION} express@4.19.2 >/dev/null 2>&1
# Record the actually-installed fast-jwt version for evidence.
RUN node -e "console.log('installed fast-jwt', require('fast-jwt/package.json').version)"
COPY server.js /app/server.js
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "server.js"]
