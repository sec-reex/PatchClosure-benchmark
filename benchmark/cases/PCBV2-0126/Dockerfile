# Per-profile image: pins one handlebars version at build time.
# No handlebars source is modified; the pinned npm package is used as-is.
FROM node:18-slim
ARG HB_VERSION
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 && npm i --no-audit --no-fund handlebars@${HB_VERSION}
COPY harness.js /app/harness.js
EXPOSE 8080
CMD ["node", "/app/harness.js"]
