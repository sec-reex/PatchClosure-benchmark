#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Identity only: Dockerfile clones LabRedesCefetRJ/WeGIA at 3.4.10.
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

TAG=""
for cand in "$REF" "v$REF"; do
  if git ls-remote --exit-code --tags "$REPO" "refs/tags/$cand" >/dev/null 2>&1; then
    TAG="$cand"
    break
  fi
done
if [[ -z "$TAG" ]]; then
  echo "git tag not found for $REPO @$REF (tried $REF and v$REF)" >&2
  exit 20
fi
SHA="$(git ls-remote --tags "$REPO" "refs/tags/$TAG" | awk '{print $1}' | head -1)"
{
  echo "repo=$REPO"
  echo "version=$REF"
  echo "tag=$TAG"
  echo "commit=${SHA:-unknown}"
  echo "cloned_at=image_build"
} > "$DEST/SOURCE_IDENTITY"
echo "source identity $REPO@$TAG (${SHA:-unknown}); cloned at image build, not host-fetched"
