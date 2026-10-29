# new-api-cve-2025-62155

new-api — CVE-2025-59146 -> CVE-2025-62155 (SSRF: the 59146 fix validates only the
initial fetch URL and follows an attacker's HTTP 302 redirect to an intranet
address without re-validating; 62155 re-validates every redirect hop).

Gold PatchClosure-Bench case. The CVE-2025-59146 SSRF fix (v0.9.0.5) validates
only the **initial** fetch URL; it follows an attacker's HTTP **302 redirect** to
an intranet address without re-validating it. CVE-2025-62155 (v0.9.6) closes the
residual by re-validating every redirect hop.

## Product
`QuantumNous/new-api` -- a self-hosted, multi-provider LLM API gateway (Go).
Authenticated users submit OpenAI-style chat completions; the server fetches
user-supplied `image_url` media **server-side** during prompt-token counting
(`service/token_counter.go` -> `DecodeUrlImageData` -> `service/download.go
DoDownloadRequest`) before relaying upstream. That fetch is the SSRF sink.

## The incomplete fix (see patch.diff)
| Version | Image | download.go behaviour |
|---|---|---|
| V0 `v0.9.0.4` | `calciumion/new-api:v0.9.0.4` | bare `http.Get(originUrl)`, **no validation** (no `ssrf_protection.go`) |
| V1 `v0.9.0.5` | `calciumion/new-api:v0.9.0.5` | `ValidateURLWithFetchSetting(initial)` then `http.Get(originUrl)` -- default client follows the 302 with **no `CheckRedirect`** => redirect target unchecked (**TARGET**) |
| V2 `v0.9.6` | `calciumion/new-api:v0.9.6` | `GetHttpClient().Get(originUrl)` where the client sets `CheckRedirect: checkRedirect`, re-validating **every hop** |

Default `fetch_setting` (v0.9.0.5) already ships SSRF protection on:
`EnableSSRFProtection:true, AllowPrivateIp:false, AllowedPorts:[80,443,8080,8443]`.
No configuration needed.

## Topology
- **attacker** sidecar: `11.11.11.10:8080` (an IP range **not** in new-api's
  private/reserved blocklist -> treated as external/allowed; 8080 is a default
  allowed port). `/redirect` -> `302 Location: http://172.31.9.9:80/internal-secret.png`.
- **canary** sidecar: `172.31.9.9:80` (private range -> blocked by the guard),
  **no published host port** -> reachable only via SSRF from the new-api server.
  Records every hit (with `${PCB_FLAG}`) and serves a 1x1 PNG.
- **newapi-v0/v1/v2**: real official images on SQLite, host ports 3010/3011/3012,
  each attached to both the `pub` and `intranet` networks.

## Payloads
- **original** (CVE-2025-59146): `image_url = http://172.31.9.9:80/internal-secret.png`
  (direct private-IP). Fetched on V0, blocked on V1.
- **residual** (CVE-2025-62155): `image_url = http://11.11.11.10:8080/redirect`
  -> 302 -> internal canary. Followed unchecked on V1, blocked on V2.

## Benign SSRF oracle
Detection = the internal canary recorded a request from the new-api server
carrying `${PCB_FLAG}`. No live-intranet exploitation; the "internal service" is a
benign canary that only logs and serves the flag.

## Run
```bash
export PCB_FLAG="pcb_$(openssl rand -hex 6)"
docker compose --profile all up -d
python3 oracle.py --gate          # prints the 4-boolean gate JSON
docker compose down -v --rmi all
```

## Gate result (2026-07-17, real Docker)
```
original_poc_reaches_flag_on_v0 = true   # canary hit @ v0
original_poc_blocked_on_v1      = true   # "request reject: private IP address not allowed: 172.31.9.9"
bypass_poc_reaches_flag_on_v1   = true   # canary hit via unchecked 302 @ v1  (residual)
residual_blocked_on_v2          = true   # "redirect to http://172.31.9.9:80/... blocked: private IP address not allowed"
```
See `repro.log` for the full transcript.

## Files
- `docker-compose.yml` -- 3 real new-api versions + attacker/canary sidecars
- `sidecars/attacker.py`, `sidecars/canary.py`
- `oracle.py` -- setup/channel/token + payload driver + canary oracle
- `original_poc.py` (given), `_heldout/bypass_poc.py` (held out)
- `patch.diff` -- v0.9.0.5 -> v0.9.6 (the redirect-revalidation fix)
- `case.json`, `repro.log`
