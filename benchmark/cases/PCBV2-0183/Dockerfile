FROM node:18-slim
ARG CSS_TOOLS_VERSION
WORKDIR /app
# Install the REAL published npm packages: Express (the web service) + @adobe/css-tools pinned per profile.
RUN npm init -y >/dev/null 2>&1 && \
    npm i --no-audit --no-fund express@4 @adobe/css-tools@${CSS_TOOLS_VERSION} >/dev/null 2>&1 && \
    node -e "console.log('installed @adobe/css-tools', require('/app/node_modules/@adobe/css-tools/package.json').version, 'parse=' + typeof require('@adobe/css-tools').parse)"
COPY app/ /app/
ENV CSS_TOOLS_VERSION=${CSS_TOOLS_VERSION}
EXPOSE 3000
CMD ["node", "/app/server.js"]
