#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Pins are git SHAs. Do NOT git ls-remote --tags (AVideo tag list hangs past 900s).
# The running product is the Dockerfile's full /app clone (~1.1G). This script only
# materializes sink identity into WORK_DIR (deleted after the run) — not a raw-file
# package for the container.
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
rm -rf "$DEST"; mkdir -p "$DEST/objects" "$DEST/vendor/erusev/parsedown"
export GIT_TERMINAL_PROMPT=0

_prove() {
  test -f "$DEST/objects/functionsSecurity.php" \
    && test -f "$DEST/vendor/erusev/parsedown/Parsedown.php"
}

# 1) Copy sink files out of the image the Dockerfile already cloned at AE_REF.
IMG="pcb-avideo-real:$V"
if docker image inspect "$IMG" >/dev/null 2>&1; then
  cid="$(docker create "$IMG" true)"
  docker cp "$cid:/app/objects/functionsSecurity.php" "$DEST/objects/functionsSecurity.php" >/dev/null
  docker cp "$cid:/app/vendor/erusev/parsedown/Parsedown.php" "$DEST/vendor/erusev/parsedown/Parsedown.php" >/dev/null
  docker rm -f "$cid" >/dev/null 2>&1 || true
  printf '%s\n' "$REF" > "$DEST/.pcb_ref"
  if _prove; then
    echo "fetched $REPO@$REF -> $DEST (sink files from $IMG; runtime is full /app clone)"
    exit 0
  fi
fi

__g() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry($i): $*" >&2; sleep 8; done; return 1; }

# 2) Sparse clone of the pinned SHA (same origin as Dockerfile). No tag search.
SPARSE="$(mktemp -d "${TMPDIR:-/tmp}/pcb0082src.XXXXXX")"
if ( git init -q "$SPARSE" && git -C "$SPARSE" remote add origin "$REPO" \
    && git -C "$SPARSE" sparse-checkout set --cone objects vendor/erusev/parsedown \
    && __g git -C "$SPARSE" fetch --depth 1 origin "$REF" \
    && git -C "$SPARSE" checkout -q FETCH_HEAD ); then
  cp -a "$SPARSE/objects/functionsSecurity.php" "$DEST/objects/functionsSecurity.php"
  mkdir -p "$DEST/vendor/erusev/parsedown"
  cp -a "$SPARSE/vendor/erusev/parsedown/Parsedown.php" "$DEST/vendor/erusev/parsedown/Parsedown.php"
  printf '%s\n' "$REF" > "$DEST/.pcb_ref"
  rm -rf "$SPARSE"
  if _prove; then
    echo "fetched $REPO@$REF -> $DEST (sparse git)"
    exit 0
  fi
fi
rm -rf "$SPARSE"

echo "fetch $REPO@$REF failed" >&2
exit 20
