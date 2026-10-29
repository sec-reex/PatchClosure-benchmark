# Real-library image for the url-parse open-redirect pair (CVE-2021-3664 -> CVE-2022-0691).
# Installs the ACTUAL `url-parse` at the exact version of the profile (build-arg) and runs the
# safe-redirect harness against it. node:20-slim ships node:http + WHATWG URL; the only npm dep is
# the pinned url-parse (and its transitive querystringify/requires-port).
FROM node:20-slim
ARG URLPARSE_VERSION=1.5.2
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund --loglevel=error "url-parse@${URLPARSE_VERSION}"
COPY harness.mjs /app/
EXPOSE 8080
CMD ["node", "/app/harness.mjs"]
