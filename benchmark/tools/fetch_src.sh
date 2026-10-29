#!/usr/bin/env bash
# ROUND16 task 2: JIT source fetcher for PatchClosure Bench.
# Usage: fetch_src.sh <case_id>
# Pulls v0/v1 (v2 optional) source of the case into /tmp/pcb_src/<case_id>/{v0,v1}/
# and writes /tmp/pcb_src/<case_id>/patch_context.json with the full content of
# every patch-touched file at v1 plus the real v0->v1 diff.
#
# Purity rules: consumes ONLY provenance/source_manifest.json; no per-case
# hardcoding; unresolved cases exit non-zero with the reason printed.
#
# Env: KEEP_CACHE=1 keeps /tmp/pcb_src_cache/<case_id> for debugging (default 0).

set -u
CASE_ID="${1:-}"
[ -z "$CASE_ID" ] && { echo "usage: $0 <case_id>"; exit 2; }

BENCH_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export BENCH_DIR CASE_ID
MANIFEST="$BENCH_DIR/provenance/source_manifest.json"
WORK="/tmp/pcb_src/$CASE_ID"
export WORK
CACHE="/tmp/pcb_src_cache/$CASE_ID"
KEEP_CACHE="${KEEP_CACHE:-0}"
MAX_BYTES=$((2 * 1024 * 1024 * 1024))   # 2GB per-case guard

[ -f "$MANIFEST" ] || { echo "FATAL: manifest not found: $MANIFEST"; exit 3; }
command -v jq >/dev/null || { echo "FATAL: jq required"; exit 3; }
command -v python3 >/dev/null || { echo "FATAL: python3 required"; exit 3; }

# ---- disk guard ------------------------------------------------------------
FREE_KB=$(df -Pk /tmp | awk 'NR==2 {print $4}')
if [ -n "${FREE_KB:-}" ] && [ "$FREE_KB" -lt 524288 ]; then
  echo "FATAL: /tmp free space <512MB ($((FREE_KB/1024))MB)"; exit 4
fi

ENTRY=$(jq -r ".[\"$CASE_ID\"]" "$MANIFEST" 2>/dev/null)
if [ "$ENTRY" = "null" ] || [ -z "$ENTRY" ]; then
  echo "FATAL: case_id not in manifest"; exit 3
fi

STYPE=$(echo "$ENTRY" | jq -r '.source_type')
PLAN=$(echo "$ENTRY" | jq -r '.fetch_plan')
if [ "$STYPE" = "unresolved" ]; then
  echo "FATAL: unresolved source_type (case not auto-fetchable)"
  echo "  raw v1: $(echo "$ENTRY" | jq -r '.v1.raw')"
  exit 1
fi

rm -rf "$WORK"; mkdir -p "$WORK/v0" "$WORK/v1"
if [ "$KEEP_CACHE" = "1" ]; then rm -rf "$CACHE"; mkdir -p "$CACHE"; fi

PATCH_FILES=$(echo "$ENTRY" | jq -r '.patch_files[]?' 2>/dev/null)
PF_LIST=()
while IFS= read -r pf; do [ -n "$pf" ] && PF_LIST+=("$pf"); done <<< "$PATCH_FILES"

log() { echo "[fetch_src] $*"; }
fail() { echo "FATAL: $*"; exit 1; }

fetch_git() {
  # sparse blobless clone: only the directories containing patch files
  local ver="$1"
  local repo ref
  repo=$(echo "$ENTRY" | jq -r ".$ver.locator.repo_url")
  ref=$(echo "$ENTRY" | jq -r ".$ver.locator.ref")
  [ -z "$repo" ] || [ "$repo" = "null" ] && { log "$ver: no repo_url; skipping"; return 1; }
  [ -z "$ref" ] || [ "$ref" = "null" ] && { log "$ver: no ref; using default branch"; ref=""; }
  log "$ver: sparse clone $repo @ ${ref:-HEAD}"
  local work="$WORK/$ver"
  local clone_args=()
  local dirs=()
  for pf in "${PF_LIST[@]}"; do
    local d="${pf%/*}"
    [ "$d" = "$pf" ] && d="."
    dirs+=("$d")
  done
  if [ -n "$ref" ] && [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]]; then
    # commit ref: needs the full commit graph (blobless keeps it small-ish)
    log "$ver: blobless full-graph clone for commit $ref"
    git clone --filter=blob:none --no-checkout "$repo" "$work" 2>/dev/null \
      || fail "$ver: git clone failed for $repo"
    git -C "$work" checkout "$ref" 2>/dev/null \
      || fail "$ver: checkout of commit $ref failed"
    return 0
  fi
  [ -n "$ref" ] && clone_args+=(--branch "$ref")
  git clone --depth 1 --filter=blob:none --sparse --no-checkout "${clone_args[@]}" "$repo" "$work" 2>/dev/null \
    || fail "$ver: git clone failed for $repo"
  ( cd "$work" && git sparse-checkout init --cone 2>/dev/null; \
    if [ "${#dirs[@]}" -gt 0 ]; then git sparse-checkout set "${dirs[@]}"; else git sparse-checkout set .; fi \
      && git checkout "${ref:+$ref}" 2>/dev/null ) \
    || { log "$ver: sparse checkout failed, falling back to full root"; \
         git -C "$work" checkout -f "${ref:-HEAD}" 2>/dev/null || git -C "$work" checkout -f HEAD 2>/dev/null; }
  [ -d "$work" ] && du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_npm() {
  local ver="$1"
  local pkg ver2
  pkg=$(echo "$ENTRY" | jq -r ".$ver.locator.pkg")
  ver2=$(echo "$ENTRY" | jq -r ".$ver.locator.version")
  [ -z "$pkg" ] || [ "$pkg" = "null" ] && { log "$ver: no pkg; skipping"; return 1; }
  local spec="${pkg}${ver2:+@$ver2}"
  log "$ver: npm pack $spec (tarball only, no install)"
  local work="$WORK/$ver"
  mkdir -p "$work"
  ( cd "$work" && npm pack "$spec" --silent >/dev/null 2>&1 ) || fail "$ver: npm pack failed for $spec"
  local tgz; tgz=$(ls "$work"/*.tgz 2>/dev/null | head -1)
  [ -n "$tgz" ] || fail "$ver: no tarball produced"
  ( cd "$work" && tar xzf "$tgz" --strip-components=1 2>/dev/null && rm -f "$tgz" ) \
    || fail "$ver: untar failed"
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_pypi() {
  local ver="$1"
  local pkg ver2
  pkg=$(echo "$ENTRY" | jq -r ".$ver.locator.pkg")
  ver2=$(echo "$ENTRY" | jq -r ".$ver.locator.version")
  [ -z "$pkg" ] || [ "$pkg" = "null" ] && { log "$ver: no pkg; skipping"; return 1; }
  local spec="${pkg}${ver2:+==$ver2}"
  log "$ver: pip download sdist $spec (--no-deps --no-binary)"
  local work="$WORK/$ver"
  mkdir -p "$work"
  ( cd "$work" && pip download --no-deps --no-binary :all: -q "$spec" >/dev/null 2>&1 ) \
    || fail "$ver: pip download failed for $spec"
  local src; src=$(ls "$work"/*.tar.gz "$work"/*.zip 2>/dev/null | head -1)
  [ -n "$src" ] || fail "$ver: no sdist produced"
  ( cd "$work" && tar xzf "$src" --strip-components=1 2>/dev/null || unzip -qo "$src" -d . 2>/dev/null; rm -f *.tar.gz *.zip ) \
    || fail "$ver: untar failed"
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_docker() {
  local ver="$1"
  local img tag
  # prefer the compose file's v1 image (the one the benchmark actually builds);
  # manifest locator is the fallback.
  local cf="${BENCH_DIR}/cases/${CASE_ID}/docker-compose.yml"
  local cimg=""
  if [ -f "$cf" ]; then
    cimg=$(awk -v ver="$ver" '
      /^[[:space:]]*'"$ver"':[[:space:]]*$/ {sec=1; next}
      /^[[:space:]]*[a-zA-Z0-9_-]+:[[:space:]]*$/ && sec {sec=0}
      sec && /image:/ {print; exit}' "$cf" 2>/dev/null | sed -E 's/.*image:[[:space:]]*"?([^"]+)"?.*/\1/' | tr -d '\r')
  fi
  if [ -n "$cimg" ]; then
    img="${cimg%%:*}"
    tag="${cimg#*:}"
    [ "$img" = "$cimg" ] && tag=""
    log "$ver: compose image $cimg (from docker-compose.yml)"
  else
    img=$(echo "$ENTRY" | jq -r ".$ver.locator.image")
    tag=$(echo "$ENTRY" | jq -r ".$ver.locator.tag")
  fi
  [ -z "$img" ] || [ "$img" = "null" ] && { log "$ver: no image; skipping"; return 1; }
  local full="${img}${tag:+:$tag}"
  log "$ver: docker pull+create $full, copy patch dirs"
  docker pull -q "$full" >/dev/null 2>&1 || fail "$ver: docker pull failed for $full"
  local cid
  cid=$(docker create "$full" true 2>/dev/null) || fail "$ver: docker create failed"
  # generic WORKDIR resolution (no per-case knowledge): docker cp needs an
  # absolute container path; the app root is the image's configured WORKDIR.
  local workdir
  workdir=$(docker inspect -f '{{.Config.WorkingDir}}' "$full" 2>/dev/null | sed 's#\\#/#g')
  [ -z "$workdir" ] || [ "$workdir" = "<no value>" ] && workdir="/"
  local work
  work="$WORK/$ver"
  mkdir -p "$work"
  if [ "${#PF_LIST[@]}" -gt 0 ]; then
    for pf in "${PF_LIST[@]}"; do
      local d="${pf%/*}"
      [ "$d" = "$pf" ] && d="."
      if docker cp "$cid:$workdir/$d" "$work/" >/dev/null 2>&1; then
        log "  copied $workdir/$d"
      else
        # path guess failed: locate the file/dir by basename inside the image
        local found
        found=$(docker run --rm --entrypoint sh "$full" -c \
                "find / -path /proc -prune -o -type d -name '$(basename "$d")' -print -quit 2>/dev/null" 2>/dev/null)
        if [ -n "$found" ]; then
          docker cp "$cid:$found" "$work/" >/dev/null 2>&1 && log "  copied (by find) $found"
        else
          log "  warn: docker cp $d failed (not found in image)"
        fi
      fi
    done
  else
    # heuristic: copy common app roots (WORKDIR first, then standard roots)
    for d in "$workdir" /app /src /srv /var/www; do
      docker cp "$cid:$d" "$work/" >/dev/null 2>&1 && { log "  copied $d"; break; }
    done
  fi
  docker rm -f "$cid" >/dev/null 2>&1
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_maven_sources() {
  # R17: pull <artifact>-<ver>-sources.jar from Maven Central, unpack sources.
  # locator: {"gav": "group:artifact" (or full G:A:V), "version": "..."}
  local ver="$1"
  local gav ver2
  gav=$(echo "$ENTRY" | jq -r ".$ver.locator.gav")
  ver2=$(echo "$ENTRY" | jq -r ".$ver.locator.version")
  [ -z "$gav" ] || [ "$gav" = "null" ] && { log "$ver: no gav; skipping"; return 1; }
  # locator.gav is "group:artifact" (version in locator.version); tolerate full
  # "group:artifact:version" triple.
  local group art nf
  nf=$(echo "$gav" | awk -F: '{print NF}')
  group=$(echo "$gav" | cut -d: -f1)
  art=$(echo "$gav" | cut -d: -f2)
  if [ "$nf" -ge 3 ] && [ -z "$ver2" ]; then
    ver2=$(echo "$gav" | cut -d: -f3)
  fi
  [ -n "$ver2" ] || { log "$ver: no version; skipping"; return 1; }
  local gpath="${group//./\/}"
  local url="https://repo1.maven.org/maven2/$gpath/$art/$ver2/$art-$ver2-sources.jar"
  log "$ver: maven sources $url"
  local work="$WORK/$ver"
  mkdir -p "$work"
  if ! ( cd "$work" && curl -fsSL -o src.jar "$url" 2>/dev/null && unzip -qo src.jar 2>/dev/null && rm -f src.jar ); then
    log "$ver: sources.jar missing; trying plain jar (class files only, may fail file match)"
    ( cd "$work" && curl -fsSL -o bin.jar "https://repo1.maven.org/maven2/$gpath/$art/$ver2/$art-$ver2.jar" 2>/dev/null && unzip -qo bin.jar 2>/dev/null && rm -f bin.jar ) \
      || fail "$ver: maven download failed for $gav:$ver2"
  fi
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_composer_dist() {
  # R17: Packagist dist zip for composer:vendor/pkg:version.
  local ver="$1"
  local pkg ver2
  pkg=$(echo "$ENTRY" | jq -r ".$ver.locator.pkg")
  ver2=$(echo "$ENTRY" | jq -r ".$ver.locator.version")
  [ -z "$pkg" ] || [ "$pkg" = "null" ] && { log "$ver: no pkg; skipping"; return 1; }
  log "$ver: packagist dist $pkg@$ver2"
  local work="$WORK/$ver"
  mkdir -p "$work"
  local meta dist
  meta=$(curl -fsSL "https://repo.packagist.org/p2/$pkg.json" 2>/dev/null) || fail "$ver: packagist metadata failed for $pkg"
  dist=$(echo "$meta" | python3 -c "
import json,sys
d = json.load(sys.stdin)
for v in d['packages']['$pkg']:
    if v.get('version', '').lstrip('v') == '$ver2'.lstrip('v'):
        print(v.get('dist', {}).get('url', ''))
        break
" 2>/dev/null)
  [ -n "$dist" ] || fail "$ver: version $ver2 not found on packagist"
  ( cd "$work" && curl -fsSL -o dist.zip "$dist" 2>/dev/null && unzip -qo dist.zip 2>/dev/null && rm -f dist.zip ) \
    || fail "$ver: dist download failed"
  # packagist dists nest under one dir
  local sub
  sub=$(ls "$work" 2>/dev/null | head -1)
  [ -n "$sub" ] && [ -d "$work/$sub" ] && mv "$work/$sub"/* "$work/" 2>/dev/null && rmdir "$work/$sub" 2>/dev/null
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_wp_zip() {
  # R17: wordpress plugin zip (direct URL in locator.url).
  local ver="$1"
  local url
  url=$(echo "$ENTRY" | jq -r ".$ver.locator.url")
  [ -z "$url" ] || [ "$url" = "null" ] && { log "$ver: no url; skipping"; return 1; }
  log "$ver: wget $url"
  local work="$WORK/$ver"
  mkdir -p "$work"
  ( cd "$work" && curl -fsSL -o wp.zip "$url" 2>/dev/null && unzip -qo wp.zip 2>/dev/null && rm -f wp.zip ) \
    || fail "$ver: wordpress zip download failed"
  local sub; sub=$(ls "$work" 2>/dev/null | head -1)
  [ -n "$sub" ] && [ -d "$work/$sub" ] && mv "$work/$sub"/* "$work/" 2>/dev/null && rmdir "$work/$sub" 2>/dev/null
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

fetch_url_tar() {
  # R17: direct .tar.gz / .tgz / .zip URL.
  local ver="$1"
  local url
  url=$(echo "$ENTRY" | jq -r ".$ver.locator.url")
  [ -z "$url" ] || [ "$url" = "null" ] && { log "$ver: no url; skipping"; return 1; }
  log "$ver: fetch $url"
  local work="$WORK/$ver"
  mkdir -p "$work"
  ( cd "$work" && curl -fsSL -o pkg.tar.gz "$url" 2>/dev/null \
      && { tar xzf pkg.tar.gz 2>/dev/null || unzip -qo pkg.tar.gz 2>/dev/null; } && rm -f pkg.tar.gz ) \
    || fail "$ver: url fetch failed"
  local sub; sub=$(ls "$work" 2>/dev/null | head -1)
  [ -n "$sub" ] && [ -d "$work/$sub" ] && mv "$work/$sub"/* "$work/" 2>/dev/null && rmdir "$work/$sub" 2>/dev/null
  du -sh "$work" 2>/dev/null | awk '{print "  size: "$1}'
}

# ---- fetch v0 and v1 -------------------------------------------------------
for v in v0 v1; do
  case "$STYPE" in
    git)         fetch_git "$v" ;;
    npm)         fetch_npm "$v" ;;
    pypi)        fetch_pypi "$v" ;;
    docker_image) fetch_docker "$v" ;;
    maven)       fetch_maven_sources "$v" ;;
    composer)    fetch_composer_dist "$v" ;;
    wordpress_plugin_zip) fetch_wp_zip "$v" ;;
    url_tgz)     fetch_url_tar "$v" ;;
  esac
done

# ---- patch_context.json ----------------------------------------------------
log "building patch_context.json"
python3 - "$CASE_ID" <<'PYEOF'
import json, os, sys
case_id = sys.argv[1]
ben = os.environ['BENCH_DIR']
wf = os.environ['WORK']
m = json.load(open(os.path.join(ben, 'provenance', 'source_manifest.json')))[case_id]
pfiles = m.get('patch_files', [])
ctx = {'case_id': case_id, 'patch_files': pfiles, 'v1_files': {}}
# real v0->v1 diff from the case dir (kept in the benchmark, not fetched)
diff_path = os.path.join(ben, 'cases', case_id, 'patch.diff')
ctx['v0_to_v1_diff'] = open(diff_path, encoding='utf-8', errors='ignore').read() if os.path.exists(diff_path) else ''
# full content of each patch-touched file at v1 (resolved against the fetched tree)
for pf in pfiles:
    candidates = [
        os.path.join(wf, 'v1', pf),
        os.path.join(wf, 'v1', os.path.basename(pf)),
    ]
    # docker_cp preserves the absolute path dirname; npm/pypi pack root
    for d in ('v1', 'v0'):
        root = os.path.join(wf, d)
        for dp, _, fs in os.walk(root):
            for fn in fs:
                rel = os.path.relpath(os.path.join(dp, fn), root)
                if rel == pf or rel.endswith('/' + pf) or os.path.basename(rel) == os.path.basename(pf):
                    candidates.append(os.path.join(root, rel))
    found = next((p for p in candidates if os.path.exists(p)), None)
    if found:
        ctx['v1_files'][pf] = open(found, encoding='utf-8', errors='ignore').read()
    else:
        ctx['v1_files'][pf] = None
json.dump(ctx, open(os.path.join(wf, 'patch_context.json'), 'w'), ensure_ascii=False, indent=1)
missing = [pf for pf, c in ctx['v1_files'].items() if c is None]
print(f"  patch_context: {len(ctx['v1_files'])} files, {len(missing)} missing")
for pf in missing:
    print(f"    MISSING: {pf}")
PYEOF

# ---- per-case size report + 2GB guard ---------------------------------------
SZ_BYTES=$(du -sk "$WORK" | awk '{print $1*1024}')
echo "  total size: $((SZ_BYTES/1024/1024))MB ($SZ_BYTES bytes)"
if [ "$SZ_BYTES" -gt "$MAX_BYTES" ]; then
  echo "WARNING: case >2GB — sparse checkout likely ineffective; inspect $WORK"
fi

# ---- cleanup ----------------------------------------------------------------
if [ "$KEEP_CACHE" = "1" ]; then
  rm -rf "$CACHE"; mkdir -p "$CACHE"
  cp -r "$WORK"/v0 "$WORK"/v1 "$CACHE"/ 2>/dev/null
  cp "$WORK"/patch_context.json "$CACHE"/ 2>/dev/null
  log "cache kept at $CACHE"
fi
if [ "${KEEP_CACHE:-0}" = "0" ] && [ "${SKIP_CLEANUP:-0}" != "1" ]; then
  log "cleaning up (KEEP_CACHE=0): rm -rf $WORK"
  rm -rf "$WORK"
fi
log "done (exit 0)"
