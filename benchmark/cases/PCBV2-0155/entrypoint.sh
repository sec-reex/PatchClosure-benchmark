#!/bin/sh
# Start the loopback flag sidecar (it keeps ${PCB_FLAG}), then start the REAL Nuxt
# production server with PCB_FLAG stripped from its env -- so the flag can only be
# obtained via a genuine loopback SSRF through the og-image module, never from the
# render process's own environment.
set -e

FLAG_PORT="${FLAG_PORT:-9111}" PCB_FLAG="${PCB_FLAG}" node /app/sidecar.mjs &

# Strip the flag from the environment the Nuxt render process inherits.
unset PCB_FLAG

export HOST="0.0.0.0"
export PORT="${APP_PORT:-8080}"
export NITRO_HOST="0.0.0.0"
export NITRO_PORT="${APP_PORT:-8080}"

exec node /app/.output/server/index.mjs
