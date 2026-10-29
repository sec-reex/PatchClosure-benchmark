#!/usr/bin/env bash
# REAL Apache Superset init for the PatchClosure-Bench case, then hand off to the real server.
# No Superset source is modified; we only run the app's OWN CLI + a small app-context seed script.
set -euo pipefail

echo "[boot] superset db upgrade ..."
superset db upgrade

echo "[boot] superset init (roles/permissions) ..."
superset init

echo "[boot] seeding flag + registering analytics DB + users ..."
# Use the SAME interpreter that runs `superset` (system python on 4.0.x, /app/.venv on 5.0.0) so
# both `import superset` and `import psycopg2` resolve.
SUPERSET_PY="$(head -1 "$(command -v superset)" | sed 's/^#!//')"
"$SUPERSET_PY" /app/pcb/bootstrap.py

echo "[boot] starting REAL Superset server (gunicorn) ..."
exec /usr/bin/run-server.sh
