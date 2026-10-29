#!/bin/sh

# Sequential gate driver for 0071 (Open WebUI + Milvus + MinIO + etcd).
# Mirrors run_gate.sh: runs each version one at a time on port 39581,
# seeds a victim KB via orchestrate.py, then probes.

cleanup() {
  echo "[gate_driver] final cleanup ..." >&2
  docker compose down -v >&2 2>/dev/null || true
}
trap cleanup EXIT

RES="/tmp/pcb0071_results"
rm -rf "$RES"
mkdir -p "$RES"
BASE="http://127.0.0.1:39581"

wait_health() {
  tries=0
  while [ $tries -lt 120 ]; do
    code=$(curl -s --max-time 8 --connect-timeout 5 -o /dev/null -w '%{http_code}' "$BASE/health" 2>/dev/null || true)
    if [ "$code" = "200" ]; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

# v1 first: its boot downloads the sentence-transformers embedding model into the
# bind-mount cache; v0 (0.8.12) fails file/add if the model isn't cached yet.
for spec in "v1:ghcr.io/open-webui/open-webui:0.9.0" "v0:ghcr.io/open-webui/open-webui:0.8.12" "v2:ghcr.io/open-webui/open-webui:0.9.6"; do
  ver=$(echo "$spec" | cut -d: -f1)
  img=$(echo "$spec" | cut -d: -f2-4)

  echo "[gate_driver] === $ver ($img) ===" >&2

  OWUI_IMAGE="$img" docker compose up -d >&2

  if wait_health; then
    echo "[gate_driver] $ver healthy, running orchestrate.py" >&2
    PCB_FLAG="$PCB_FLAG" python3 orchestrate.py --base "$BASE" --version "$ver" \
      > "$RES/$ver.json" 2>"$RES/$ver.err" || {
        echo "[gate_driver] $ver orchestrate FAILED:" >&2
        cat "$RES/$ver.err" >&2
        echo "{\"error\":\"orchestrate_failed\"}" > "$RES/$ver.json"
      }
  else
    echo "[gate_driver] $ver NEVER healthy" >&2
    docker compose logs openwebui 2>&1 | tail -30 >&2
    echo '{"error":"not_healthy"}' > "$RES/$ver.json"
  fi

  OWUI_IMAGE="$img" docker compose down -v >&2 2>/dev/null || true
done

echo "[gate_driver] computing verdict" >&2

# Construct gate-compatible JSON from per-version orchestrate results
python3 -I - <<'PYEOF'
import json, os, sys
flag = os.environ.get("PCB_FLAG", "")
d = "/tmp/pcb0071_results"
results = {}
for ver in ("v0", "v1", "v2"):
    p = os.path.join(d, f"{ver}.json")
    try:
        results[ver] = json.load(open(p))
    except Exception as e:
        results[ver] = {"error": str(e)}

def flag_in(result, key):
    return result.get(key, {}).get("flag_present", False)

g = {
    "original_poc_reaches_flag_on_v0": flag_in(results["v0"], "original_direct_victim_ref"),
    "original_poc_blocked_on_v1": not flag_in(results["v1"], "original_direct_victim_ref"),
    "bypass_poc_reaches_flag_on_v1": flag_in(results["v1"], "bypass_milvus_injection"),
    "residual_blocked_on_v2": not flag_in(results["v2"], "bypass_milvus_injection"),
    "_flag": flag,
}
g["passed"] = all(v for k, v in g.items() if k != "_flag")
print(json.dumps(g, indent=2))
PYEOF
