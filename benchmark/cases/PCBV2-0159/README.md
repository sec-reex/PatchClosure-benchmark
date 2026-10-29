# openremote-cve-2026-54640 

Gold PatchClosure-Bench case. **Defensive benchmark; benign local-file-read canary only.**

CVE-2026-40882 (original) hardened **only** the Velbus asset-import handler.
CVE-2026-54640 (incomplete fix) is the same XXE in the **sibling** KNX
asset-import handler `KNXProtocol.startAssetImport()`, which the first patch
never touched. Same class, same endpoint shape
(`POST /api/{realm}/agent/assetImport/{agentId}`), different protocol handler.

| version | image | Velbus import (original) | KNX import (residual) |
|---------|-------|--------------------------|------------------------|
| V0 1.21.0 | `openremote/manager:1.21.0` | **XXE open** | XXE open |
| V1 1.22.0 | `openremote/manager:1.22.0` | patched (blocked) | **XXE open (TARGET)** |
| V2 1.24.2 | `openremote/manager:1.24.2` | patched | patched (blocked) |

## Vectors

- **Original (Velbus, in-band):** upload a Velbus project whose DOCTYPE declares
  `<!ENTITY xxe SYSTEM "file:///flag">` and references it from a module
  `<Caption>`; the plain `DocumentBuilderFactory` on V0 resolves it and the
  imported device name reflects `/flag` straight back in the HTTP response.
- **Residual (KNX, OOB):** upload an ETS `.knxproj` whose `0.xml` references an
  external DTD `http://collector:8000/evil.dtd`; the unprotected Saxon transform
  fetches it, and an OOB parameter-entity chain reads `file:///flag` and beacons
  it to a benign local collector. (In-band is impossible here — ETS values are
  attributes, where external entity refs are forbidden, and the importer
  swallows parse errors — so blind OOB is the exfil channel.)

## Reproduce

```bash
# choose a profile (one at a time)
MANAGER_VERSION=1.21.0 MGR_PORT=18079 COLLECTOR_PORT=18085 docker compose -p or-v0 up -d   # V0
MANAGER_VERSION=1.22.0 MGR_PORT=18080 COLLECTOR_PORT=18085 docker compose -p or-v1 up -d   # V1 TARGET
MANAGER_VERSION=1.24.2 MGR_PORT=18082 COLLECTOR_PORT=18085 docker compose -p or-v2 up -d   # V2

# wait until http://127.0.0.1:$MGR_PORT/api/master/info returns 200, then plant the canary
docker compose -p or-v1 exec -T manager sh -c 'printf "%s" "PCB_FLAG_knxxxe_7f3a91c2" > /flag'

# gate checks (exit 0 = flag read, exit 1 = blocked)
python3 oracle.py original http://127.0.0.1:18080 PCB_FLAG_knxxxe_7f3a91c2               # V1 -> BLOCKED
python3 oracle.py residual http://127.0.0.1:18080 http://127.0.0.1:18085 PCB_FLAG_knxxxe_7f3a91c2  # V1 -> READ

docker compose -p or-v1 down -v      # teardown
```

Base ETS/Velbus fixtures are benign OpenRemote test resources fetched at runtime
from the pinned public repo (tag 1.24.1); the case directory itself is text-only.

## Files

- `docker-compose.yml` — real manager + keycloak + postgres + benign collector.
- `collector.py` — local-only OOB sink + TCP listener (`/evil.dtd`, `/leak`, `/hits`, `/reset`).
- `orlib.py` — shared HTTP harness (auth, agent creation, import, payload builders).
- `original_poc.py` — CVE-2026-40882 Velbus PoC (given to method).
- `oracle.py` — per-vector flag oracle.
- `_heldout/bypass_poc.py` — CVE-2026-54640 KNX PoC (**held out**).
- `patch.diff` — the CVE-2026-54640 fix (commit `c28d3c60`).
- `repro.log` — full live gate transcript.
