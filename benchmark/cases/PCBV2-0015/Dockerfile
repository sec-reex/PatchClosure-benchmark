FROM node:18-bookworm-slim
ARG POSTCSS_VERSION
WORKDIR /app
# Install the REAL published npm packages: Express (the web service) + postcss pinned per profile.
RUN npm init -y >/dev/null 2>&1 && \
    npm i --no-audit --no-fund express@4 postcss@${POSTCSS_VERSION} >/dev/null 2>&1 && \
    node -e "require('postcss'); console.log('installed postcss', require('/app/node_modules/postcss/package.json').version)"
COPY app/ /app/
ENV POSTCSS_VERSION=${POSTCSS_VERSION}
EXPOSE 3000
CMD ["node", "/app/server.js"]
