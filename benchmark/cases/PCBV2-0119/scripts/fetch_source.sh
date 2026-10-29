#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Download the official GitHub release tarball into CASE_DIR/srccache (Dockerfile COPY)
# and leave an identity copy under --dest. Do not git-clone the whole repo.
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
[[ "${TYPE}" == "url_tgz" ]] || { echo "source_type=$TYPE must be url_tgz" >&2; exit 20; }
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
[[ -n "$REF" ]] || { echo "empty $V version in .source.env" >&2; exit 20; }
U="$(printf '%s' "${URL:?url_tgz case 缺 URL}" | sed "s|__REF__|$REF|g")"

CACHE_DIR="$CASE_DIR/srccache"
mkdir -p "$CACHE_DIR"
TGZ="$CACHE_DIR/glpi-${REF}.tgz"

download() {
  local dest="$1"
  echo "fetch_source: downloading $U" >&2
  curl -fL --retry 4 --retry-delay 3 --max-time 300 -o "$dest" "$U"
}

need=1
if [[ -f "$TGZ" ]] && gzip -t "$TGZ" 2>/dev/null; then
  sz="$(wc -c < "$TGZ" | tr -d ' ')"
  if [[ "$sz" -gt 1000000 ]]; then
    need=0
    echo "fetch_source: reusing $TGZ ($sz bytes)" >&2
  fi
fi
if [[ "$need" == "1" ]]; then
  tmp="$TGZ.partial"
  ok=0
  for i in 1 2 3; do
    if download "$tmp" && gzip -t "$tmp" 2>/dev/null; then
      mv -f "$tmp" "$TGZ"
      ok=1
      break
    fi
    echo "retry($i): $U" >&2
    sleep 8
  done
  [[ "$ok" == "1" ]] || { echo "url_tgz download failed: $U" >&2; exit 20; }
fi

rm -rf "$DEST"
mkdir -p "$DEST"
cp -f "$TGZ" "$DEST/glpi-${REF}.tgz"
printf 'product=glpi\nversion=%s\ntarball=glpi-%s.tgz\nurl=%s\n' "$REF" "$REF" "$U" > "$DEST/source.identity"
echo "fetched url_tgz glpi-$REF -> srccache + $DEST"
