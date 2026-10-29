#!/bin/bash
# Plant the per-run canary OUTSIDE the app dir, (optionally) install + seed the REAL Concrete CMS,
# then serve over HTTP. Install/seed logic lives in the mounted /work/seed.sh so it can be iterated
# without rebuilding the (expensive) composer-install image.
set -e

# --- benign canary: random ${PCB_FLAG} in /canary/flag.txt, outside /app -----------------------
mkdir -p /canary
printf '%s\n' "${PCB_FLAG:?PCB_FLAG must be set to the per-run canary token}" > /canary/flag.txt
chmod 644 /canary/flag.txt
# only root+www-data readable enough; render path (php as www-data) must be able to read it
chown root:www-data /canary/flag.txt || true

# --- run apache in background so the seed script can drive it over http -------------------------
apache2-foreground &
APACHE_PID=$!

# --- install + seed (real CLI installer, real Express object, real block) -----------------------
if [ -f /work/seed.sh ]; then
    bash /work/seed.sh 2>&1 | sed 's/^/[seed] /' || echo "[seed] FAILED (see above)"
fi

# --- fix permissions so apache (www-data) can write to cache/config after seed (root) ----------
chown -R www-data:www-data /app/application/files /app/application/config 2>/dev/null || true
chmod -R 775 /app/application/files /app/application/config 2>/dev/null || true

echo "[entrypoint] ready; apache pid=$APACHE_PID"
wait "$APACHE_PID"
