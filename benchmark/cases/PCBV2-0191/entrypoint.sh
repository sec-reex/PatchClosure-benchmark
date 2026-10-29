#!/bin/sh
# Plant the per-run benign canary in the ENVIRONMENT (not in simple-git's official code).
# ${PCB_FLAG} is written to a file OUTSIDE the app dir; the injected git upload-pack "command" merely
# cats it into /canary/out.txt, which the harness reads back. No real payload, no persistence.
set -e
: "${PCB_FLAG:?PCB_FLAG must be set to the per-run canary token}"
mkdir -p /canary
printf '%s' "${PCB_FLAG}" > /canary/flag.txt
chmod 0644 /canary/flag.txt
rm -f /canary/out.txt
# LOCAL bare repo as the clone source so git spawns the (canary) upload-pack locally -- no network.
if [ ! -d /srv/repo.git ]; then
  git init -q --bare /srv/repo.git
fi
exec node /app/harness.mjs
