#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Download official GNU bash-4.3.tar.gz + bash-4.3-patches (not a git clone).
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
[[ "${TYPE}" == "url_tgz" ]] || { echo "source_type=$TYPE must be url_tgz (GNU FTP)" >&2; exit 20; }

LAST_PATCH=24
[[ "$V" == "v1" ]] && LAST_PATCH=25

rm -rf "$DEST"
mkdir -p "$DEST/patches"

download() {
  local dest="$1" url="$2"
  curl -fL --retry 4 --retry-delay 3 --max-time 180 -o "$dest" "$url"
}

TGZ="$DEST/bash-4.3.tar.gz"
ok=0
for U in "${URL}" "${MIRROR_URL}"; do
  [[ -n "${U:-}" ]] || continue
  echo "fetch_source: downloading $U" >&2
  if download "$TGZ" "$U" && gzip -t "$TGZ" 2>/dev/null; then
    ok=1
    USED_URL="$U"
    break
  fi
  echo "fetch_source: retry next mirror after $U" >&2
done
[[ "$ok" == "1" ]] || { echo "url_tgz download failed for bash-4.3.tar.gz" >&2; exit 20; }

PATCH_OK=0
for PBASE in "${PATCH_BASE}" "${MIRROR_PATCH_BASE}"; do
  [[ -n "${PBASE:-}" ]] || continue
  fail=0
  for i in $(seq 1 "$LAST_PATCH"); do
    n="$(printf '%03d' "$i")"
    if ! download "$DEST/patches/bash43-$n" "$PBASE/bash43-$n"; then
      fail=1
      break
    fi
  done
  if [[ "$fail" == "0" ]]; then
    PATCH_OK=1
    USED_PATCH="$PBASE"
    break
  fi
done
[[ "$PATCH_OK" == "1" ]] || { echo "patch download failed (001-$LAST_PATCH)" >&2; exit 20; }

mkdir -p "$DEST/src"
if ! tar xzf "$TGZ" -C "$DEST/src"; then
  echo "url_tgz extract failed" >&2
  exit 20
fi

{
  printf 'product=gnu-bash\n'
  printf 'version=4.3\n'
  printf 'profile=%s\n' "$V"
  printf 'patches=001-%03d\n' "$LAST_PATCH"
  printf 'tarball_url=%s\n' "$USED_URL"
  printf 'patch_base=%s\n' "$USED_PATCH"
} > "$DEST/source.identity"
echo "fetched url_tgz bash-4.3 + patches 001-$LAST_PATCH -> $DEST"
