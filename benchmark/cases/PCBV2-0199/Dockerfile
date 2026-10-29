# Per-profile image: pins one angular-expressions version at build time.
# No angular-expressions source is modified; the pinned npm package is used as-is.
FROM node:20-slim
ARG AE_VERSION
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 && npm i --no-audit --no-fund angular-expressions@${AE_VERSION}
COPY harness.js /app/harness.js
EXPOSE 8080
CMD ["node", "/app/harness.js"]
