#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Clone the WHOLE comfyanonymous/ComfyUI tree at the exact CVE commit SHA.
# Runtime still builds from Dockerfile.comfy (same commits); this is the protocol fetch.
set -euo pipefail
V=""; DEST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) V="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 30 ;;
  esac
done
[[ -n "$V" && -n "$DEST" ]] || { echo "usage: --version v0|v1 --dest DIR" >&2; exit 30; }
[[ "$V" == "v0" || "$V" == "v1" ]] || { echo "bad version: $V" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
rm -rf "$DEST"
mkdir -p "$DEST"
__g() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry($i): $*" >&2; sleep 8; done; return 1; }

# Exact commit SHA (not a fuzzy tag like 0.3.7-era). Prefer shallow fetch of that object.
if ! ( git init -q "$DEST" && cd "$DEST" \
        && git remote add origin "$REPO" \
        && __g git fetch -q --depth 1 origin "$REF" \
        && git checkout -q FETCH_HEAD ); then
  echo "shallow fetch $REF failed; cloning then checkout" >&2
  rm -rf "$DEST"
  __g git clone --filter=blob:none --quiet "$REPO" "$DEST" || { echo "clone failed" >&2; exit 20; }
  git -C "$DEST" checkout -q "$REF" || { echo "checkout $REF failed" >&2; exit 20; }
fi
HEAD="$(git -C "$DEST" rev-parse HEAD)"
echo "fetched $REPO@$REF -> $DEST (HEAD=$HEAD)"
# Sanity: real ComfyUI tree (main.py / server.py), not a 20-line stub.
test -s "$DEST/main.py" && test -s "$DEST/server.py" || { echo "missing main.py/server.py in cloned tree" >&2; exit 20; }
wc -l "$DEST/main.py" "$DEST/server.py"
