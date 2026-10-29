#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Official ghcr.io/open-webui/open-webui:<ver> is the SUT. Do not clone the repo.
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
echo "docker_image 源：运行镜像即源码载体；identity=$IMG:$REF" >&2
echo "fetched docker_image $IMG@$REF -> $DEST (runtime image)"
