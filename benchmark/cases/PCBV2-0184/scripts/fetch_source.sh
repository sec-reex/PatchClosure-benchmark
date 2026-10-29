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
  BRANCH=""
  # 基础候选：$REF / v$REF / release- / release/ / release(无分隔,如 ofbiz release18.12.09) / REL-${REF//./_}
  CAND=("$REF" "v$REF" "v${REF//./_}" "release-$REF" "release/$REF" "releases/$REF" "release$REF" "REL-${REF//./_}" "rel-$REF")
  # 追加去后缀候选（如 18.12.09-era -> 18.12.09；0.7.0-beta -> 0.7.0）
  if [[ "$REF" == *-* ]]; then
    BASE="${REF%-*}"
    CAND+=("$BASE" "v$BASE" "release-$BASE" "release/$BASE" "release$BASE" "REL-${BASE//./_}")
  fi
  for cand in "${CAND[@]}"; do
    if git ls-remote --exit-code --tags "$REPO" "refs/tags/$cand" >/dev/null 2>&1; then
      BRANCH="$cand"
      break
    fi
  done
  if [[ -z "$BRANCH" ]]; then
    # 模糊后缀匹配：tag 以版本号结尾（分隔符含 / - _ . @ 等）
    for P in "$REF" "${REF%-*}"; do
      FZ="$(git ls-remote --tags "$REPO" 2>/dev/null | sed 's|.*refs/tags/||' | grep -E "(^|@|/|-|_|\.)${P//./\.}$" | head -1 || true)"
      if [[ -n "$FZ" ]]; then BRANCH="$FZ"; break; fi
    done
  fi
  __g() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry($i): $*" >&2; sleep 8; done; return 1; }
  if [[ -n "$BRANCH" ]]; then
    __g git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$DEST" || { echo "clone $BRANCH failed" >&2; exit 20; }
  else
    ( git init -q "$DEST" && cd "$DEST" \
        && git remote add origin "$REPO" \
        && __g git fetch -q --depth 1 origin "$REF" \
        && git checkout -q FETCH_HEAD ) || { echo "fetch $REF failed" >&2; exit 20; }
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
elif [[ "$TYPE" == "pypi" ]]; then
  PKG="${PKG:?pypi case 需 .source.env 配 PKG}"
  rm -rf "$DEST"; mkdir -p "$DEST"
  if ! python3 -m pip download "$PKG==$REF" --no-deps -d "$DEST" >/dev/null 2>&1; then
    echo "pip download failed: $PKG==$REF" >&2
    exit 20
  fi
  ART="$(ls -1 "$DEST"/*.whl "$DEST"/*.tar.gz "$DEST"/*.zip 2>/dev/null | head -1 || true)"
  [[ -n "$ART" ]] || { echo "pypi artifact not found for $PKG==$REF" >&2; exit 20; }
  case "$ART" in
    *.whl|*.zip) unzip -qo "$ART" -d "$DEST" ;;
    *.tar.gz) tar xzf "$ART" -C "$DEST" ;;
    *) echo "unknown pypi artifact: $ART" >&2; exit 20 ;;
  esac
  rm -f "$ART"
  echo "fetched pypi $PKG@$REF -> $DEST"
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
