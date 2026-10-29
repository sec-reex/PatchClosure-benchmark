# Faithful-core image for the npm `simple-git` git-CONFIG-injection sink
# (CVE-2022-25912 -> CVE-2026-6951). One image; the version is selected by HARNESS_VER, which picks
# which side-by-side tree the harness require()s. CRITICAL: each version is installed in its OWN tree
# (/app/v0, /app/v1, /app/v2) so it gets its OWN @simple-git/argv-parser -- the guard whose config-key
# blocklist is the whole subject of this pair. v1 PINS argv-parser to the vulnerable 1.0.3 (via an
# `overrides` in v1/package.json); v2 (simple-git 3.36.0) floats to the fixed 1.1.x. A single shared
# node_modules would hoist ONE argv-parser and destroy the v1-vulnerable / v2-fixed differential.
# node:20-slim ships a git recent enough to honour the ext:: transport and checkout filters.
FROM node:20-slim
# git: simple-git shells out to the real `git` binary; the injection sink IS git's own config handling.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git config --global user.email "ci@benchmark.local" \
    && git config --global user.name "pcb-ci" \
    && git config --global init.defaultBranch main
WORKDIR /app
# Install the three trees separately so each keeps its own argv-parser (see per-tree package.json).
COPY v0/package.json /app/v0/
COPY v1/package.json /app/v1/
COPY v2/package.json /app/v2/
RUN cd /app/v0 && npm install --no-audit --no-fund --loglevel=error
RUN cd /app/v1 && npm install --no-audit --no-fund --loglevel=error
RUN cd /app/v2 && npm install --no-audit --no-fund --loglevel=error
COPY harness.mjs /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
