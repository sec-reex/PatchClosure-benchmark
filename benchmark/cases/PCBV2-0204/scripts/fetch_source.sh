#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Identity only: Dockerfile clones salesagility/SuiteCRM at v7.14.5 / v7.15.0.
# A second host-side clone of the full tree is wasted time and disk.
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

# Canonical GitHub tags: v7.14.5 / v7.15.0 / v7.15.1. ls-remote is best-effort;
# a GitHub blip must not fail identity-only fetch (SUT is the image clone).
TAG=""
SHA=""
for i in 1 2 3 4; do
  for cand in "v$REF" "$REF"; do
    line="$(git ls-remote --tags "$REPO" "refs/tags/${cand}" 2>/dev/null | awk 'NF{print; exit}' || true)"
    if [[ -n "$line" ]]; then
      SHA="${line%%[[:space:]]*}"
      TAG="$cand"
      break 2
    fi
  done
  echo "retry($i): git ls-remote $REPO tags for $REF" >&2
  sleep $((3 * i))
done
if [[ -z "$TAG" ]]; then
  TAG="v$REF"
  echo "ls-remote unavailable; recording Dockerfile tag $TAG" >&2
fi
{
  echo "repo=$REPO"
  echo "version=$REF"
  echo "tag=$TAG"
  echo "commit=${SHA:-unknown}"
  echo "cloned_at=image_build"
} > "$DEST/SOURCE_IDENTITY"
echo "source identity $REPO@$TAG (${SHA:-unknown}); cloned at image build, not host-fetched"
