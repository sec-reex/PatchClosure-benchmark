#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR — 按需拉取准确版本源码（shallow）。
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
if [[ "$TYPE" == "git" ]]; then
  if git ls-remote --exit-code --tags "$REPO" "refs/tags/$REF" >/dev/null 2>&1; then
    git clone --quiet --depth 1 --branch "$REF" "$REPO" "$DEST" || { echo "clone failed" >&2; exit 20; }
  else
    git init -q "$DEST" && cd "$DEST" \
      && git remote add origin "$REPO" \
      && git fetch -q --depth 1 origin "$REF" \
      && git checkout -q FETCH_HEAD || { echo "fetch $REF failed" >&2; exit 20; }
  fi
  echo "fetched $REPO@$REF -> $DEST"
elif [[ "$TYPE" == "wordpress_plugin_zip" ]]; then
  SLUG="${SLUG:-${REPO##*/}}"
  SLUG="${SLUG%.git}"
  URL="https://downloads.wordpress.org/plugin/${SLUG}.${REF}.zip"
  if ! curl -fsSL "$URL" -o "$DEST.zip" 2>/dev/null; then
    echo "wp-plugin download failed: $URL" >&2
    exit 20
  fi
  mkdir -p "$DEST"
  if ! unzip -q "$DEST.zip" -d "$DEST" 2>/dev/null; then
    echo "wp-plugin unzip failed" >&2
    exit 20
  fi
  rm -f "$DEST.zip"
  echo "fetched wordpress plugin $SLUG@$REF -> $DEST"
elif [[ "$TYPE" == "url_tgz" ]]; then
  [[ -n "${URL:-}" ]] || { echo "url_tgz case 缺 .source.env 的 URL" >&2; exit 30; }
  U="$(printf '%s' "$URL" | sed "s|__REF__|$REF|g")"
  if ! curl -fsSL "$U" -o "$DEST.tar.gz" 2>/dev/null; then
    echo "url_tgz download failed: $U" >&2
    exit 20
  fi
  mkdir -p "$DEST"
  if ! tar xzf "$DEST.tar.gz" -C "$DEST" 2>/dev/null; then
    echo "url_tgz extract failed" >&2
    exit 20
  fi
  rm -f "$DEST.tar.gz"
  echo "fetched url_tgz $REF -> $DEST"
elif [[ "$TYPE" == "npm" ]]; then
  PKG="${PKG:?npm case 需 .source.env 配 PKG}"
  if ! npm pack "$PKG@$REF" --pack-destination "$(dirname "$DEST")" >/dev/null 2>&1; then
    echo "npm pack failed: $PKG@$REF" >&2
    exit 20
  fi
  mkdir -p "$DEST"
  TGZ="$(ls -t "$(dirname "$DEST")"/*.tgz 2>/dev/null | head -1)"
  [[ -n "$TGZ" ]] || { echo "npm tarball not found" >&2; exit 20; }
  tar xzf "$TGZ" -C "$DEST" --strip-components=1 2>/dev/null
  rm -f "$TGZ"
  echo "fetched npm $PKG@$REF -> $DEST"
elif [[ "$TYPE" == "docker_image" ]]; then
  IMG="${IMAGE:?docker_image case 需 .source.env 配 IMAGE}"
  echo "docker_image 源：运行镜像即源码载体（构建上下文/镜像层）；源码 identity 以镜像 tag 为准" >&2
  echo "fetched docker_image $IMG@$REF -> $DEST (runtime image)"
elif [[ "$TYPE" == "maven" ]]; then
  GAV="${GAV:?maven case 需 .source.env 配 GAV=group:artifact（不含版本）}"
  G="${GAV%%:*}"; A="${GAV##*:}"
  GP="${G//./\/}"
  URL="https://repo1.maven.org/maven2/${GP}/${A}/${REF}/${A}-${REF}-sources.jar"
  if ! curl -fsSL "$URL" -o "$DEST.jar" 2>/dev/null; then
    URL2="https://repo1.maven.org/maven2/${GP}/${A}/${REF}/${A}-${REF}.jar"
    curl -fsSL "$URL2" -o "$DEST.jar" 2>/dev/null || { echo "maven download failed" >&2; exit 20; }
  fi
  mkdir -p "$DEST"
  (cd "$DEST" && jar xf "$DEST.jar" 2>/dev/null || unzip -qo "$DEST.jar" 2>/dev/null) || { echo "maven extract failed" >&2; exit 20; }
  rm -f "$DEST.jar"
  echo "fetched maven $GAV@$REF -> $DEST"
else
  echo "source_type=$TYPE not supported by template" >&2; exit 20
fi
