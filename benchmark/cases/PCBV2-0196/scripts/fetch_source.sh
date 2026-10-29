#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Library identity = published Maven Central spring-webmvc + spring-beans.
# Also docker-pull the official Tomcat / Maven builder images used at runtime.
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

_dl() {
  local gav="$1" dest="$2"
  local g="${gav%%:*}" a="${gav##*:}"
  local gp="${g//./\/}"
  local url="https://repo1.maven.org/maven2/${gp}/${a}/${REF}/${a}-${REF}.jar"
  local i
  for i in 1 2 3; do
    if curl -fsSL --retry 3 --retry-delay 2 -o "$dest/${a}-${REF}.jar" "$url"; then
      echo "fetched maven $gav@$REF -> $dest/${a}-${REF}.jar"
      return 0
    fi
    echo "maven download retry $i: $url" >&2
    sleep 4
  done
  echo "maven download failed: $url" >&2
  exit 20
}

_dl "${GAV:?maven case 需 .source.env 配 GAV}" "$DEST"
_dl "${GAV_BEANS:?maven case 需 GAV_BEANS}" "$DEST"

if [[ "$V" == "v0" ]]; then
  docker pull "${MAVEN_V0:?}"
  docker pull "${TOMCAT_V0:?}"
else
  docker pull "${MAVEN_V1:?}"
  docker pull "${TOMCAT_V1:?}"
fi
echo "fetched docker images for $V (official Tomcat + Maven builder)"
