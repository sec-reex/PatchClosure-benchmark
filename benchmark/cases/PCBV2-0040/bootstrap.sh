#!/bin/bash
# Bootstrap script for Superset: installs psycopg2, initializes DB, starts server.
set -e

echo "[bootstrap] Installing psycopg2-binary..."
pip install --quiet --no-cache-dir psycopg2-binary 2>&1 | tail -1

# Ensure user-installed packages are on PYTHONPATH (lean images may install to
# user site-packages while the venv python does not include it by default)
USER_SITE=$(python3 -c "import site; print(site.getusersitepackages())" 2>/dev/null || true)
if [ -n "$USER_SITE" ] && [ -d "$USER_SITE" ]; then
    export PYTHONPATH="${USER_SITE}:${PYTHONPATH:-}"
    echo "[bootstrap] Added $USER_SITE to PYTHONPATH"
fi

echo "[bootstrap] Running superset db upgrade..."
superset db upgrade 2>&1 | tail -3

echo "[bootstrap] Creating admin user..."
superset fab create-admin \
    --username admin \
    --firstname Admin \
    --lastname Admin \
    --email admin@pcb.test \
    --password admin123 2>&1 || true

echo "[bootstrap] Running superset init..."
superset init 2>&1 | tail -3

echo "[bootstrap] Superset initialized. Starting server..."
exec gunicorn \
    --bind 0.0.0.0:8088 \
    --workers 2 \
    --timeout 120 \
    --limit-request-line 0 \
    --limit-request-field_size 0 \
    "superset.app:create_app()"
