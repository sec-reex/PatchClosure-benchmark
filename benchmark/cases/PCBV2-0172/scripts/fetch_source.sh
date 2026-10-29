#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR
# Package identity = published Packagist pimcore/pimcore (no git clone).
# Runtime still installs the whole package via Dockerfile `composer require`.
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
PKG="${PKG:?composer case 需 .source.env 配 PKG}"
rm -rf "$DEST"; mkdir -p "$DEST"

python3 - "$PKG" "$REF" "$DEST" <<'PY'
import json, os, sys, time, urllib.request, zipfile, io, ssl

pkg, ref, dest = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context()
headers = {"User-Agent": "pcb-fetch"}

def get(url, timeout=90):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read()

def write_ident(ident, note):
    open(os.path.join(dest, "packagist-identity.json"), "w").write(
        json.dumps(ident, indent=2) + "\n"
    )
    print(f"fetched composer {pkg}@{ref} -> {dest} ({note})")

# Runtime image does composer require; dest is identity-only.
# Known published pins if Packagist metadata is flaky.
FALLBACK = {
    "10.5.20": {
        "package": pkg,
        "version": "10.5.20",
        "dist": {
            "url": "https://api.github.com/repos/pimcore/pimcore/zipball/4bccaed3f2a2aebee1a6f1655199c76d3efa2762",
            "type": "zip",
            "reference": "4bccaed3f2a2aebee1a6f1655199c76d3efa2762",
        },
        "source": {
            "url": "https://github.com/pimcore/pimcore.git",
            "type": "git",
            "reference": "4bccaed3f2a2aebee1a6f1655199c76d3efa2762",
        },
    },
    "10.5.21": {
        "package": pkg,
        "version": "10.5.21",
        "dist": {
            "url": "https://api.github.com/repos/pimcore/pimcore/zipball/25ad8674886f2b938243cbe13e33e204a2e35cc3",
            "type": "zip",
            "reference": "25ad8674886f2b938243cbe13e33e204a2e35cc3",
        },
        "source": {
            "url": "https://github.com/pimcore/pimcore.git",
            "type": "git",
            "reference": "25ad8674886f2b938243cbe13e33e204a2e35cc3",
        },
    },
}

meta = None
last_err = None
for attempt in range(1, 4):
    try:
        meta = json.loads(get(f"https://packagist.org/packages/{pkg}.json", timeout=60))
        last_err = None
        break
    except Exception as e:
        last_err = e
        sys.stderr.write(f"packagist metadata retry {attempt}/3: {e}\n")
        time.sleep(3 * attempt)

if meta is None:
    fb = FALLBACK.get(ref)
    if fb:
        write_ident(fb, "packagist identity fallback; dist skipped")
        sys.exit(0)
    sys.stderr.write(f"packagist metadata failed: {last_err}\n")
    sys.exit(20)

vers = (meta.get("package") or {}).get("versions") or {}
hit = vers.get(ref) or vers.get(f"v{ref}")
if not hit:
    fb = FALLBACK.get(ref)
    if fb:
        write_ident(fb, "packagist identity fallback; version key missing")
        sys.exit(0)
    sys.stderr.write(f"packagist: {pkg} {ref} not found\n")
    sys.exit(20)

ident = {
    "package": pkg,
    "version": ref,
    "dist": hit.get("dist") or {},
    "source": hit.get("source") or {},
}
open(os.path.join(dest, "packagist-identity.json"), "w").write(json.dumps(ident, indent=2) + "\n")

du = (hit.get("dist") or {}).get("url")
if not du:
    print(f"fetched composer {pkg}@{ref} -> {dest} (packagist identity)")
    sys.exit(0)

blob = None
last_err = None
for attempt in range(1, 4):
    try:
        blob = get(du, timeout=120)
        last_err = None
        break
    except Exception as e:
        last_err = e
        sys.stderr.write(f"packagist dist retry {attempt}/3: {e}\n")
        time.sleep(4 * attempt)
if blob is None:
    sys.stderr.write(f"packagist dist skipped after retries: {last_err}\n")
    print(f"fetched composer {pkg}@{ref} -> {dest} (packagist identity; dist unavailable)")
    sys.exit(0)

try:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        zf.extractall(dest)
except Exception as e:
    sys.stderr.write(f"packagist dist extract failed (identity kept): {e}\n")
    print(f"fetched composer {pkg}@{ref} -> {dest} (packagist identity)")
    sys.exit(0)
print(f"fetched composer {pkg}@{ref} -> {dest}")
PY
