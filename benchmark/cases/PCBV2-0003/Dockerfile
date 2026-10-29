FROM node:20-slim
ARG VITE_VERSION
WORKDIR /app
# Minimal Vite project: only vite installed at the pinned version. No app business
# code beyond an empty index.html so the dev server boots. The /@fs/ middleware
# (the CVE1/CVE2 sink) is active regardless.
RUN npm init -y >/dev/null 2>&1 \
 && npm install --no-audit --no-fund --no-progress vite@${VITE_VERSION}
COPY index.html /app/index.html
COPY vite.config.js /app/vite.config.js
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 5173
ENTRYPOINT ["/entrypoint.sh"]
