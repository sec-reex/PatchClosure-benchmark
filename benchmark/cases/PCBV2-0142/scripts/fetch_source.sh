#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR — 按需拉取准确版本源码（shallow）。
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
source "$CASE_DIR/.source.env"
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
rm -rf "$DEST"; mkdir -p "$DEST"
if [[ "$TYPE" == "git" ]]; then
  BRANCH=""
  if git ls-remote --exit-code --tags "$REPO" "refs/tags/$REF" >/dev/null 2>&1; then
    BRANCH="$REF"
  elif git ls-remote --exit-code --tags "$REPO" "refs/tags/v$REF" >/dev/null 2>&1; then
    BRANCH="v$REF"
  fi
  __g() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry($i): $*" >&2; sleep 8; done; return 1; }
  if [[ -n "$BRANCH" ]]; then
    __g git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$DEST" || { echo "clone $BRANCH failed" >&2; exit 20; }
  else
    ( git init -q "$DEST" && cd "$DEST" \
        && git remote add origin "$REPO" \
        && __g git fetch -q --depth 1 origin "$REF" \
        && git checkout -q FETCH_HEAD ) || { echo "fetch $REF failed" >&2; exit 20; }
  fi
  echo "fetched $REPO@$REF -> $DEST"
else
  echo "source_type=$TYPE not supported" >&2; exit 20
fi
