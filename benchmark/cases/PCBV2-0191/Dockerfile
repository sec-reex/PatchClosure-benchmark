# Faithful-core image for the npm `simple-git` git-argument-injection sink
# (CVE-2022-25860 -> CVE-2026-28291). One image; the version is selected by HARNESS_VER, which picks
# which side-by-side npm-aliased `simple-git` build the harness require()s (simple-git@3.15.1=V0,
# simple-git@3.31.1=V1, simple-git@3.32.0=V2 -- see package.json). The argument-injection sink under
# test (git.clone() forwarding a crafted --upload-pack/-u option past block-unsafe-operations-plugin)
# is pure JS and runtime-independent; the REAL published simple-git bytes require() and run identically
# here. node:20-slim ships a git recent enough to honour --upload-pack over file:// transport.
FROM node:20-slim
# git: simple-git shells out to the real `git` binary; the injection sink IS git's own option parser.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git config --global user.email "ci@benchmark.local" \
    && git config --global user.name "pcb-ci" \
    && git config --global init.defaultBranch main
WORKDIR /app
COPY package.json /app/
RUN npm install --no-audit --no-fund --loglevel=error
COPY harness.mjs /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
