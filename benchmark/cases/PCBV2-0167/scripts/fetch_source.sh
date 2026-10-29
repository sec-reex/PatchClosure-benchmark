#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Shallow-clone the official pheditor git tag (whole repo) into --dest.
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
[[ -n "$REF" ]] || { echo "empty $V version in .source.env" >&2; exit 20; }
[[ "$TYPE" == "git" ]] || { echo "source_type=$TYPE must be git" >&2; exit 20; }

rm -rf "$DEST"
mkdir -p "$DEST"

__g() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry($i): $*" >&2; sleep 8; done; return 1; }

cloned=0
if __g git clone --quiet --depth 1 --branch "$REF" "$REPO" "$DEST"; then
  cloned=1
fi
if [[ "$cloned" != "1" ]]; then
  echo "fetch_source: git clone failed, trying GitHub tag tarball $REF" >&2
  tmp="$(mktemp -d)"
  tgz="$tmp/pheditor-${REF}.tar.gz"
  url="https://github.com/pheditor/pheditor/archive/refs/tags/${REF}.tar.gz"
  if __g curl -fsSL --retry 3 --retry-delay 4 -o "$tgz" "$url"; then
    tar xzf "$tgz" -C "$DEST" --strip-components=1
    rm -rf "$tmp"
  else
    rm -rf "$tmp"
    echo "fetch $REPO@$REF failed" >&2
    exit 20
  fi
fi

if [[ ! -f "$DEST/pheditor.php" ]]; then
  echo "fetch_source: $DEST missing pheditor.php (not the full pheditor tag)" >&2
  exit 20
fi
echo "fetched $REPO@$REF -> $DEST"
