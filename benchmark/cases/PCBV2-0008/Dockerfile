FROM node:18-slim
ARG SEMVER_REGEX_VERSION
WORKDIR /app
# Install the REAL published npm packages: Express (the web service) + semver-regex pinned per profile.
RUN npm init -y >/dev/null 2>&1 && \
    npm i --no-audit --no-fund express@4 semver-regex@${SEMVER_REGEX_VERSION} >/dev/null 2>&1 && \
    node -e "console.log('installed semver-regex', require('semver-regex/package.json').version)"
COPY app/ /app/
ENV SEMVER_REGEX_VERSION=${SEMVER_REGEX_VERSION}
EXPOSE 3000
CMD ["node", "/app/server.js"]
