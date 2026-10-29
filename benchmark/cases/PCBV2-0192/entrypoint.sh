#!/bin/sh
# Plant the per-run benign canary in the ENVIRONMENT (not in simple-git's official code).
# ${PCB_FLAG} is written to a file OUTSIDE the app dir; the injected git command merely cats it into
# /canary/out.txt, which the harness reads back. No real payload, no persistence, no network.
set -e
: "${PCB_FLAG:?PCB_FLAG must be set to the per-run canary token}"
mkdir -p /canary
printf '%s' "${PCB_FLAG}" > /canary/flag.txt
chmod 0644 /canary/flag.txt
rm -f /canary/out.txt

# LOCAL bare repo used as the clone source for the RESIDUAL (filter.<x>.smudge) path. It contains a
# tracked file whose .gitattributes assigns it the `pcb` filter, so a plain `git clone` of it performs
# a checkout that invokes the injected `filter.pcb.smudge` command -- entirely locally, no network.
if [ ! -d /srv/repo.git ]; then
  W=$(mktemp -d)
  git init -q "$W"
  printf 'data\n' > "$W/data.txt"
  printf 'data.txt filter=pcb\n' > "$W/.gitattributes"
  (cd "$W" && git add -A && git commit -q -m init)
  git clone -q --bare "$W" /srv/repo.git
  rm -rf "$W"
fi

exec node /app/harness.mjs
