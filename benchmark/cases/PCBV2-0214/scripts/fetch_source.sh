#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Official library/xwiki:<tag> is the SUT. Do not clone xwiki-platform.git.
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
[[ "${TYPE}" == "docker_image" ]] || { echo "source_type=$TYPE must be docker_image" >&2; exit 20; }
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
IMG="${IMAGE:?docker_image case 需 .source.env 配 IMAGE}"
rm -rf "$DEST"; mkdir -p "$DEST"
printf 'image=%s\ntag=%s\n' "$IMG" "$REF" > "$DEST/image.identity"

_pull() {
  local spec="$1"
  local i ok=0
  for i in 1 2 3 4 5; do
    if docker pull "$spec"; then
      ok=1
      break
    fi
    echo "retry($i): docker pull $spec" >&2
    sleep $((8 * i))
  done
  [[ "$ok" == "1" ]] || { echo "docker pull $spec failed" >&2; return 1; }
}

_pull "${IMG}:${REF}" || exit 20
_pull "mariadb:11.4" || exit 20
echo "docker_image 源：运行镜像即源码载体；identity=$IMG:$REF" >&2
echo "fetched docker_image $IMG@$REF -> $DEST (runtime image)"
