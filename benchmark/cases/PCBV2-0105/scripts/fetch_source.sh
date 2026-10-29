#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Library identity = published RubyGems rack (no git clone).
# Runtime still `gem install rack -v ${RACK_VERSION}` in the Dockerfile.
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
PKG="${PKG:-rack}"
rm -rf "$DEST"; mkdir -p "$DEST"
URL="https://rubygems.org/downloads/${PKG}-${REF}.gem"
if ! curl -fsSL -o "$DEST/${PKG}-${REF}.gem" "$URL"; then
  echo "rubygems download failed: $URL" >&2
  exit 20
fi
printf 'package=%s\nversion=%s\nsource=https://rubygems.org/gems/%s\n' "$PKG" "$REF" "$PKG" > "$DEST/SOURCE_PIN"
echo "fetched rubygems $PKG@$REF -> $DEST"
