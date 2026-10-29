#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Library identity = published Maven Central jinjava jar (no git clone).
# Runtime jars are still pulled by the Dockerfile from Maven Central.
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
GAV="${GAV:?maven case 需 .source.env 配 GAV=group:artifact}"
G="${GAV%%:*}"; A="${GAV##*:}"
GP="${G//./\/}"
URL="https://repo1.maven.org/maven2/${GP}/${A}/${REF}/${A}-${REF}.jar"
if ! curl -fsSL -o "$DEST/${A}-${REF}.jar" "$URL"; then
  echo "maven download failed: $URL" >&2
  exit 20
fi
echo "fetched maven $GAV@$REF -> $DEST"
