# Faithful-core image for the npm `shell-quote` quote() OS-command-injection sink
# (pre-CVE 1.7.2  ->  CVE-2021-42740 fix 1.7.3 [backtick escaped, TARGET]  ->  CVE-2026-9277 fix 1.8.4 [op allowlist]).
# One image, one role selected by HARNESS_VER: an HTTP endpoint whose quote() escaping is the REAL,
# per-version published shell-quote, feeding child_process.exec('/bin/sh -c ...'). node:20-slim; the
# three published shell-quote versions are installed side-by-side via npm aliases (package.json), so the
# harness invokes the exact published bytes of shell-quote@1.7.2 (V0), @1.7.3 (V1) and @1.8.4 (V2).
FROM node:20-slim
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund
COPY harness.mjs /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
