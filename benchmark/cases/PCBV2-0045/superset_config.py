# PatchClosure-Bench superset_config.py overlay for INJ-01-superset-denylist.
#
# Mounted into the REAL apache/superset image. This turns on exactly the feature the CVE
# pair guards: the DISALLOWED_SQL_FUNCTIONS denylist that gates user-submitted SQL Lab
# queries (superset/db_engine_specs/base.py::BaseEngineSpec.execute ->
# sql_parse.check_sql_functions_exist). The postgresql set is verbatim from Superset's own
# default superset/config.py.
#
# Nothing here lifts or reimplements Superset logic; it only supplies deployment settings
# (SECRET_KEY, sync SQL Lab, the denylist) so the real app boots and enforces the real guard.
import os

# Superset refuses to start on the built-in default SECRET_KEY; supply a fixed one for the bench.
SECRET_KEY = "pcb-superset-benchmark-fixed-secret-key-0123456789-abcdefghijklmnop"

# The real security control the CVE pair hardens. Engine key "postgresql" == PostgresEngineSpec.engine.
DISALLOWED_SQL_FUNCTIONS = {
    "postgresql": {"version", "query_to_xml", "inet_server_addr", "inet_client_addr"},
    "clickhouse": {"url"},
    "mysql": {"version"},
}

# Run SQL Lab synchronously (no Celery/Redis in this bench): /api/v1/sqllab/execute/ returns
# the result rows inline in the JSON response, which is what the oracle reads over HTTP.
FEATURE_FLAGS = {"SQLLAB_BACKEND_PERSISTENCE": False}
SQLLAB_CTAS_NO_LIMIT = True

# Keep the HTTP surface simple/deterministic for the external probe.
TALISMAN_ENABLED = False
WTF_CSRF_ENABLED = True
# Allow the analytics DB connection string to be used as-is.
PREVENT_UNSAFE_DB_CONNECTIONS = False
