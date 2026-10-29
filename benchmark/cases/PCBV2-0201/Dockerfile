# Per-profile image: pins one n8n-workflow version at build time.
# No n8n source is modified; the pinned npm package's real expression sandbox is
# imported VERBATIM by harness.js (faithful core).
FROM node:20-slim
ARG NW_VERSION
WORKDIR /app
RUN npm init -y >/dev/null 2>&1 && npm i --no-audit --no-fund n8n-workflow@${NW_VERSION}
COPY harness.js /app/harness.js
EXPOSE 8080
# Entrypoint plants the per-run canary file (${PCB_FLAG}) OUTSIDE app code, then starts
# the harness. The flag also lives in the container env (process.env.PCB_FLAG).
CMD ["sh", "-c", "mkdir -p /canary && printf '%s' \"$PCB_FLAG\" > /canary/flag.txt && exec node /app/harness.js"]
