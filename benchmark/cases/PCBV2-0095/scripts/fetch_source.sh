#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Official DataEase image is the SUT. Do not clone the huge git repo.
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
pull_one() {
  local spec="$1" i alt=""
  case "$spec" in
    mysql:*|redis:*) alt="registry.cn-hangzhou.aliyuncs.com/library/${spec}" ;;
  esac
  for i in 1 2 3 4 5; do
    if docker image inspect "$spec" >/dev/null 2>&1; then
      return 0
    fi
    if docker pull "$spec"; then
      return 0
    fi
    if [[ -n "$alt" ]] && docker pull "$alt"; then
      docker tag "$alt" "$spec"
      return 0
    fi
    echo "retry($i): docker pull ${spec}" >&2
    sleep $((6 * i))
  done
  echo "docker pull ${spec} failed" >&2
  return 1
}
# Sidecars first so compose --pull never cannot race a concurrent --rmi.
pull_one "mysql:8.0" || exit 20
pull_one "redis:6.2" || exit 20
pull_one "${IMG}:${REF}" || exit 20
echo "docker_image 源：运行镜像即源码载体；identity=$IMG:$REF" >&2
echo "fetched docker_image $IMG@$REF -> $DEST (runtime image)"
