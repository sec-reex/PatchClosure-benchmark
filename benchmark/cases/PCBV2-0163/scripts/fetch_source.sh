#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Library identity = published Maven Central owasp-java-html-sanitizer jar.
# Do not clone java-html-sanitizer.git. Runtime still uses the same GAV via Dockerfile.
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
URL="https://repo1.maven.org/maven2/${GP}/${A}/${REF}/${JAR}"
ok_dl=0
for i in 1 2 3 4 5; do
  if curl -fL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 180 \
       -o "$DEST/$JAR" "$URL"; then
    ok_dl=1
    break
  fi
  echo "maven Central retry $i: $URL" >&2
  sleep $((4 * i))
done
if [[ "$ok_dl" != "1" ]]; then
  echo "maven download failed: $URL" >&2
  exit 20
fi
{
  printf 'gav=%s\n' "$GAV"
  printf 'version=%s\n' "$REF"
  printf 'jar=%s\n' "$JAR"
} > "$DEST/PIN.txt"
echo "fetched maven $GAV@$REF -> $DEST/$JAR"

if [[ -n "${MAVEN_IMAGE:-}" ]]; then
  if docker image inspect "$MAVEN_IMAGE" >/dev/null 2>&1; then
    echo "maven builder image $MAVEN_IMAGE already local"
  elif docker pull "$MAVEN_IMAGE" >/dev/null; then
    echo "fetched docker image $MAVEN_IMAGE"
  else
    echo "warn: docker pull $MAVEN_IMAGE failed; Dockerfile may still use a local/cache layer" >&2
  fi
fi
