#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# pyLoad has no release tag 0.5.0b3. Pins are git commits. GitHub refuses
# `git fetch --depth 1 origin <short-sha>` (unadvertised object), so we
# download the commit tarball instead of searching tags.
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
rm -rf "$DEST"; mkdir -p "$DEST"

__curl() {
  local i url="$1" out="$2"
  for i in 1 2 3; do
    if curl -fsSL --retry 2 --retry-delay 3 "$url" -o "$out"; then
      return 0
    fi
    echo "retry($i): curl $url" >&2
    sleep 8
  done
  return 1
}

# Hex SHA (7–40): GitHub archive. Do not ls-remote tags (0.5.0b3 does not exist).
if [[ "$REF" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  TGZ="$(mktemp "${TMPDIR:-/tmp}/pcb0179.XXXXXX.tar.gz")"
  URL="https://github.com/pyload/pyload/archive/${REF}.tar.gz"
  __curl "$URL" "$TGZ" || { echo "tarball fetch failed: $URL" >&2; rm -f "$TGZ"; exit 20; }
  if ! tar xzf "$TGZ" -C "$DEST" --strip-components=1; then
    echo "tarball extract failed: $URL" >&2
    rm -f "$TGZ"
    exit 20
  fi
  rm -f "$TGZ"
  echo "fetched $REPO@$REF -> $DEST"
  exit 0
fi

echo "expected a git SHA in .source.env, got REF=$REF" >&2
exit 20
