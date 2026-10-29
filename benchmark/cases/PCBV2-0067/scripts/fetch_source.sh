#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Library identity = published org.jenkins-ci.main:remoting from the Jenkins Maven repo.
# Do not clone remoting.git. Runtime still uses the same GAV via Dockerfile.
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

GAV="${GAV:?maven case 需 .source.env 配 GAV}"
G="${GAV%%:*}"; A="${GAV##*:}"
GP="${G//./\/}"
JAR="${A}-${REF}.jar"
URLS=(
  "https://repo.jenkins-ci.org/public/${GP}/${A}/${REF}/${JAR}"
  "https://repo1.maven.org/maven2/${GP}/${A}/${REF}/${JAR}"
)
ok=0
for url in "${URLS[@]}"; do
  if curl -fsSL -o "$DEST/$JAR" "$url"; then
    ok=1
    echo "fetched maven $GAV@$REF -> $DEST/$JAR ($url)"
    break
  fi
done
if [[ "$ok" != "1" ]]; then
  echo "maven download failed for $GAV@$REF" >&2
  exit 20
fi
{
  printf 'gav=%s\n' "$GAV"
  printf 'version=%s\n' "$REF"
  printf 'jar=%s\n' "$JAR"
} > "$DEST/PIN.txt"

if [[ -n "${MAVEN_IMAGE:-}" ]]; then
  docker pull "$MAVEN_IMAGE" >/dev/null
  echo "fetched docker image $MAVEN_IMAGE"
fi
