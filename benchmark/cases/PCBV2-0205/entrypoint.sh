#!/bin/bash
set -e

# --- PatchClosure-Bench entrypoint ---
# Plants the serialized payload in two locations:
#   1. /tmp/payload.session          (for CVE-2020-9484 original PoC -- path traversal)
#   2. /usr/local/tomcat/sessions-extra/payload.session
#      (for CVE-2021-25329 residual -- sibling-dir bypass of String.startsWith check)

echo "[PCB] Flag value: ${PCB_FLAG:?PCB_FLAG must be set}"

# Create store directory (FileStore expects it)
mkdir -p /usr/local/tomcat/sessions

# Plant payload for original PoC (direct path traversal to /tmp)
cp /opt/pcb/payload.session /tmp/payload.session

# Plant payload for residual PoC (sibling directory bypass)
mkdir -p /usr/local/tomcat/sessions-extra
cp /opt/pcb/payload.session /usr/local/tomcat/sessions-extra/payload.session

# Ensure ROOT webapp exists with a minimal index
mkdir -p /usr/local/tomcat/webapps/ROOT
echo "OK" > /usr/local/tomcat/webapps/ROOT/index.html

echo "[PCB] Payloads planted, starting Tomcat..."
exec catalina.sh run
