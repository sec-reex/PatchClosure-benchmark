# REAL Apache Superset benchmark image for INJ-01-superset-denylist.
# FROM the OFFICIAL apache/superset image (per SS_TAG build-arg) -- no Superset source copied.
# We only add a config overlay + an init entrypoint that boots the real app.
#   SS_TAG=4.0.1 -> V0 (pre CVE-2024-39887: no DISALLOWED_SQL_FUNCTIONS enforcement)
#   SS_TAG=4.0.2 -> V1 (CVE-2024-39887 fix; TARGET; sqlparse denylist, comment-inline bypass open)
#   SS_TAG=5.0.0 -> V2 (CVE-2025-55674 fix; sqlglot denylist; comment-inline residual closed)
ARG SS_TAG=4.0.2
FROM apache/superset:${SS_TAG}

USER root
ENV SUPERSET_CONFIG_PATH=/app/pcb/superset_config.py
RUN mkdir -p /app/pcb
COPY superset_config.py /app/pcb/superset_config.py
COPY bootstrap.py       /app/pcb/bootstrap.py
COPY bootstrap.sh       /app/pcb/bootstrap.sh
RUN chmod +x /app/pcb/bootstrap.sh && chown -R superset /app/pcb
# Install the PostgreSQL driver into the SAME interpreter that runs `superset` (system python on
# 4.0.x, the /app/.venv venv on 5.0.0). This is a normal Superset deployment step -- the real app
# needs a DB driver to reach the analytics postgres; no Superset source is touched. (5.0.0's base
# image ships no postgres driver at all, so this is required for the analytics connection to work.)
RUN SUPERSET_PY="$(head -1 "$(command -v superset)" | sed 's/^#!//')" && \
    SUPERSET_VENV="$(dirname "$(dirname "$SUPERSET_PY")")" && \
    echo "installing psycopg2-binary into $SUPERSET_PY (venv=$SUPERSET_VENV)" && \
    ( "$SUPERSET_PY" -m pip install --no-cache-dir "psycopg2-binary==2.9.9" \
      || VIRTUAL_ENV="$SUPERSET_VENV" uv pip install --python "$SUPERSET_PY" "psycopg2-binary==2.9.9" ) && \
    "$SUPERSET_PY" -c "import psycopg2; print('psycopg2', psycopg2.__version__)"

USER superset
ENTRYPOINT []
CMD ["/app/pcb/bootstrap.sh"]
