#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Identity only: the Dockerfile clones apache/ofbiz-framework at OFBIZ_REF during
# image build. A second host-side git clone is wasted time and disk.
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
printf '%s\n' "$REPO@$REF" > "$DEST/SOURCE_IDENTITY"
echo "source identity $REPO@$REF (cloned at image build, not host-fetched)"
