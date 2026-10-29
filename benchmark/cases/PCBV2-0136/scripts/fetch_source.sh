#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Official ghcr.io/danny-avila/librechat:<ver> is the SUT. Do not clone the git repo.
# Overlay extract flakes: reuse a complete local/pin tag; otherwise retry pull
# with backoff and drop a partial tag between attempts.
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
[[ "$V" == "v0" || "$V" == "v1" ]] || { echo "bad version: $V" >&2; exit 20; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"
[[ "${TYPE}" == "docker_image" ]] || { echo "source_type=$TYPE must be docker_image" >&2; exit 20; }
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
IMG="${IMAGE:?docker_image case 需 .source.env 配 IMAGE}"
rm -rf "$DEST"; mkdir -p "$DEST"
printf 'image=%s\ntag=%s\n' "$IMG" "$REF" > "$DEST/image.identity"

pin_of() {
  case "$1" in
    ghcr.io/danny-avila/librechat:*) echo "pcb-0136-librechat:${1##*:}" ;;
    mongo:*) echo "pcb-0136-mongo:${1##*:}" ;;
    *) echo "pcb-0136-${1//[:\/]/-}" ;;
  esac
}

ensure_tag() {
  local spec="$1"
  local pin
  pin="$(pin_of "$spec")"
  if docker image inspect "$spec" >/dev/null 2>&1; then
    docker tag "$spec" "$pin" >/dev/null 2>&1 || true
    echo "docker_image already local: $spec" >&2
    return 0
  fi
  if docker image inspect "$pin" >/dev/null 2>&1; then
    docker tag "$pin" "$spec"
    echo "docker_image restored $spec from $pin" >&2
    return 0
  fi
  local i
  for i in 1 2 3 4 5 6; do
    if docker pull "$spec"; then
      docker tag "$spec" "$pin" >/dev/null 2>&1 || true
      return 0
    fi
    echo "retry($i): docker pull $spec" >&2
    docker rmi -f "$spec" >/dev/null 2>&1 || true
    sleep $((10 + i * 5))
  done
  echo "docker pull $spec failed" >&2
  return 1
}

ensure_tag "${IMG}:${REF}" || exit 20
ensure_tag "mongo:7.0" || exit 20
echo "docker_image 源：运行镜像即源码载体；identity=$IMG:$REF" >&2
echo "fetched docker_image $IMG@$REF -> $DEST (runtime image)"
