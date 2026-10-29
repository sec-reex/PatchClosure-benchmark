#!/bin/sh
# Plant the benign canary in the ENVIRONMENT (never in app code): the per-run ${PCB_FLAG} goes into a file
# OUTSIDE the app, plus a no-argument flag-reader script the injected command substitution invokes.
set -e
: "${PCB_FLAG:?set PCB_FLAG to the per-run canary token}"

mkdir -p /canary
printf '%s\n' "$PCB_FLAG" > /canary/flag.txt
chmod 0644 /canary/flag.txt

# Benign no-arg reader used by the backtick command substitution: `/canary/rf` -> cat /canary/flag.txt.
# Single absolute word (no spaces) so the injected `<denoPath> ... `/canary/rf`` stays one shell token.
printf '#!/bin/sh\ncat /canary/flag.txt\n' > /canary/rf
chmod 0755 /canary/rf

# Select the OFFICIAL deno binary for this profile. Deno.execPath() (hence the version-specific
# transformDenoShellCommand) is exactly this binary's published bytes.
case "${HARNESS_VER:-v1}" in
  v0) DENO=/opt/deno/v0/bin/deno ;;
  v2) DENO=/opt/deno/v2/bin/deno ;;
  *)  DENO=/opt/deno/v1/bin/deno ;;
esac

exec "$DENO" run -A /app/harness.ts
