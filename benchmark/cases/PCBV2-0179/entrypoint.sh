#!/bin/sh
# Start the real pyLoad web UI. Config/db are preseeded in the image;
# this only re-applies the bind address if a reset recreated defaults.
set -e
: "${PCB_FLAG:?set PCB_FLAG}"
USERDIR="${PYLOAD_USERDIR:-/root/.pyload}"
STORAGEDIR="${PYLOAD_STORAGEDIR:-/downloads}"
mkdir -p "$USERDIR" "$STORAGEDIR" /data/dl
if [ ! -f "$USERDIR/settings/pyload.cfg" ]; then
  timeout 45 pyload --userdir "$USERDIR" --storagedir "$STORAGEDIR" --dry-run || true
fi
if [ -f "$USERDIR/settings/pyload.cfg" ]; then
  sed -i -E 's/(ip host : "IP [Aa]ddress" = )localhost/\10.0.0.0/' "$USERDIR/settings/pyload.cfg" || true
fi
exec pyload --userdir "$USERDIR" --storagedir "$STORAGEDIR"
