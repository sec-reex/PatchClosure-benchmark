#!/usr/bin/env bash
# prepare.sh — install python-socketio client into WORK_DIR (oracle talks real socket.io).
set -euo pipefail
: "${WORK_DIR:?}"
mkdir -p "$WORK_DIR/pydeps"
PY="${PCB_PYTHON:-python3}"
if "$PY" -c "import socketio, websocket" 2>/dev/null; then
  echo "prepare: python-socketio already importable"
  exit 0
fi
ok=0
for i in 1 2 3; do
  if "$PY" -m pip install -q -t "$WORK_DIR/pydeps" "python-socketio[client]" websocket-client; then
    ok=1
    break
  fi
  echo "prepare: pip retry $i" >&2
  sleep 5
done
[[ "$ok" == "1" ]] || { echo "prepare: pip install python-socketio failed" >&2; exit 1; }
PYTHONPATH="$WORK_DIR/pydeps${PYTHONPATH:+:$PYTHONPATH}" \
  "$PY" -c "import socketio, websocket" || { echo "prepare: socketio import failed" >&2; exit 1; }
echo "prepare: python-socketio installed in $WORK_DIR/pydeps"
