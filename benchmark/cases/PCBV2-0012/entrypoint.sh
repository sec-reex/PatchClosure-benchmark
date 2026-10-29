#!/bin/sh
# Plant the benign canary in the ENVIRONMENT (never in app code): the per-run ${PCB_FLAG} goes into a
# file OUTSIDE the app, plus two no-argument flag-reader scripts the injected command can invoke.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"

mkdir -p /canary
printf '%s\n' "$PCB_FLAG" > /canary/flag.txt
chmod 0644 /canary/flag.txt

# Residual (CVE-2026-9277) newline injection runs an absolute single-word command: /canary/rf
printf '#!/bin/sh\ncat /canary/flag.txt\n' > /canary/rf
chmod 0755 /canary/rf

# Seed (CVE-2021-42740) backtick `[A-z]:` bypass yields the colon-glued command-substitution word ":;rf"
# (the leading ":" + literal ";" are part of the command NAME), resolved via PATH. Plant it on PATH.
printf '#!/bin/sh\ncat /canary/flag.txt\n' > "/usr/local/bin/:;rf"
chmod 0755 "/usr/local/bin/:;rf"

exec node /app/harness.mjs
