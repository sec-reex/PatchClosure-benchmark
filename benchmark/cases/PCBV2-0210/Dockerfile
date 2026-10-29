# DEPRECATED / STALE — DO NOT USE.
#
# This Dockerfile built the BANNED verbatim-lift harness (harness/server.js), which copied
# Uptime Kuma's socket.io auth sink into a minimal Node app instead of booting the real app.
# The case has been rebuilt to boot the REAL published Uptime Kuma images. It is no longer
# referenced by docker-compose.yml. Left in place per the no-rm policy.
#
# The real case is defined entirely by:
#   docker-compose.yml   -> louislam/uptime-kuma:1.23.2 / 1.23.3 / 1.23.10
#   oracle.py            -> real socket.io client (python-socketio) differential + gate
#
# See repro.log and case.json (audit.method = "real-app-rebuild").
