# koel-cve-2026-54491 

**Pair:** CVE-2026-47260 (original, V1 fix) → **CVE-2026-54491** (incomplete-fix bypass, V2 fix)
**Product:** Koel — self-hosted personal music/podcast streaming server (Laravel/PHP).
**Root cause:** CWE-918 SSRF. The V1 fix added a per-hop redirect-target validator to only
**one** of several sibling server-side fetch paths.

## Mechanism (incomplete fix)

Koel 9.3.5 fixed CVE-2026-47260 by adding `Network::isSafeUrl()` to four fetchers and a
per-hop Guzzle `on_redirect` validator (commit `be1e867`) to **`EpisodePlayable`** only.
The sibling **`PodcastService::getStreamableUrl()`** — the OPTIONS/HEAD "is this directly
streamable?" probe that *also* runs on every episode play — kept only the initial
`isSafeUrl()` check and still follows a cross-host 302 with **no** per-hop validation.
Koel 9.7.1 (commit `c264a3d5`) routes `getStreamableUrl()` through
`SafeHttp::getPinnedGuzzleClient()`, applying per-hop validation to every fetch leg.

A single authenticated **non-admin** `GET /play/{episode}` makes
`PodcastStreamerAdapter::stream()` run **both** legs against the same `episode->path`
(an attacker URL that 302-redirects to an internal host):

| Leg | Version guard | Detection |
|-----|---------------|-----------|
| **Original** `EpisodePlayable` `Http::sink()->get()` (full-read) | V0 none → V1 `isSafeUrl`+`on_redirect` | `${PCB_FLAG}` bytes in the `/play` response body |
| **Residual** `getStreamableUrl()` OPTIONS/HEAD (blind sibling) | V1 `isSafeUrl` only → V2 pinned per-hop | internal canary `/hits.log` non-empty |

## Versions (official Docker images)

| Profile | Image | Role | Port |
|---------|-------|------|------|
| v0 | `phanan/koel:9.3.2` | pre-fix, both legs SSRF | 39820 |
| v1 | `phanan/koel:9.3.5` | **TARGET** — original blocked, residual open | 39821 |
| v2 | `phanan/koel:9.7.1` | residual closed | 39822 |

## Topology

- `publicnet` 11.0.0.0/24 — `attacker` 11.0.0.10 = PHP-*public* (`isPublicHost`=true, passes
  the initial `SafeUrl`); serves the podcast RSS + a 302 to the canary.
- `internalnet` 10.99.0.0/24 — `canary` 10.99.0.192 = PHP-*private* (`isPublicHost`=false, the
  redirect-guard target); **no host port**, serves `${PCB_FLAG}` and logs every hit.

## Run

```bash
python3 oracle.py            # full 4-boolean gate across v0/v1/v2 (brings up + sets up each)
# or individually (containers must be up + set up):
python3 original_poc.py --port 39820   # original SSRF @v0 (flag) ; --port 39821 -> blocked
python3 _heldout/bypass_poc.py --port 39821  # residual SSRF @v1 (canary) ; --port 39822 -> blocked
```

## Gate result (real Docker, fresh `down -v` then up)

```
original_poc_reaches_flag_on_v0 : true   (/play body @v0 contains the flag; canary GET+OPTIONS)
original_poc_blocked_on_v1      : true   (no flag in /play body @v1; on_redirect throws)
bypass_poc_reaches_flag_on_v1   : true   (canary 'OPTIONS /hit' @v1; getStreamableUrl sibling)
residual_blocked_on_v2          : true   (canary log empty @v2; pinned per-hop validation)
VERDICT: PASS
```

## Teardown

```bash
docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all && docker image prune -f
```

Benign SSRF-to-sidecar only; the canary serves a random per-run token, never a real secret.
