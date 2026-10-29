# admidio-cve-2026-42194 

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

**Pair:** CVE-2026-32812 (V1 incomplete fix) → **CVE-2026-42194** / GHSA-hcjj-chvw-fmw9 (V2 fix)
**Product:** Admidio (PHP membership/user-management system) · **Sink:** `modules/sso/fetch_metadata.php`

## The incomplete fix
`fetch_metadata.php` fetches an admin-supplied `?url=` server-side and echoes the body back.

- **V0 = 5.0.6** — `file_get_contents($url)` after only `FILTER_VALIDATE_URL`. No scheme/IP check → SSRF + local file read (CVE-2026-32812).
- **V1 = 5.0.7** — CVE-2026-32812 fix: require `https://`, then `$ip = gethostbyname($host)` and reject private/reserved IPs via `FILTER_FLAG_NO_PRIV_RANGE|NO_RES_RANGE`. **But** the fetch is `curl_init($url)` on the *original hostname* with **no `CURLOPT_RESOLVE`**, so libcurl re-resolves the host a second time → **check-vs-fetch DNS-rebinding TOCTOU**. This is the target.
- **V2 = 5.0.9** — CVE-2026-42194 fix (commit `f6b7a96`): `curl_setopt($ch, CURLOPT_RESOLVE, ["$host:443:$ip"])` pins cURL to the exact IP `gethostbyname()` validated → CHECK IP == FETCH IP.

## Differential (real Docker, gate_passed)
| probe | V0 5.0.6 | V1 5.0.7 | V2 5.0.9 |
|---|---|---|---|
| `https://seed.pcb.test/` (direct, CVE-2026-32812) | **FLAG** | blocked (private IP) | blocked |
| `https://rebind.pcb.test/` (DNS-rebind, CVE-2026-42194) | decoy (no flag) | **FLAG** | blocked (IP pinned) |

`seed.pcb.test` always resolves to the internal canary `10.99.0.192` (PHP-private). `rebind.pcb.test`
rebinds per A-query: the guard's `gethostbyname` **CHECK** gets the public decoy `198.51.100.50`
(passes the filter), libcurl's **FETCH** gets the canary `10.99.0.192` → SSRF to `${PCB_FLAG}`.

## Layout
- `docker-compose.yml` / `Dockerfile` / `entrypoint.sh` — real Admidio (Ubuntu+Apache+PHP8.3+composer, git tag per version) + MariaDB + sidecars.
- `dns_server.py` — UDP DNS rebinder (per-client-IP A-query parity). `tls_server.py` — HTTPS canary/decoy. `certs/` — PCB test CA + multi-SAN server cert (trusted in each image).
- `original_poc.py` (given seed) · `_heldout/bypass_poc.py` (held-out residual) · `oracle.py` (install wizard + admin login + SSRF probe + gate) · `patch.diff` · `repro.log`.

## Run
```bash
export PCB_FLAG="PCBFLAG_$(openssl rand -hex 16)"
docker compose --profile v0 --profile v1 --profile v2 up -d --build
python3 oracle.py --wait      # installs all versions over HTTP, then runs the gate
docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all
```
