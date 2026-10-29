# gogs-cve-2026-47267

CVE-2022-1285 -> CVE-2026-47267 (incomplete-fix chain, webhook SSRF via redirects).

- V0 = Gogs 0.12.7  (webhook delivery does NOT re-check local-network addresses)
- V1 = Gogs 0.14.2  (CVE-2022-1285 fix: delivery-time localCIDR re-check; redirects still followed) <- target
- V2 = Gogs 0.14.3  (CVE-2026-47267 fix: delivery refuses ALL redirects)

## Infrastructure (shared compose network)

- `canary`: internal-only HTTP service (`http://canary:8000/flag`), NO host port.
  Returns the PCB flag as plain text. Proof of SSRF reachability.
- `attacker`: HTTP service on host port 33690; every request answers 302 ->
  `Location: http://canary:8000/flag`. Simulates an attacker-controlled webhook
  receiver that is legitimately allowlisted.
- `v1`/`v2` app.ini: `[security] LOCAL_NETWORK_ALLOWLIST = attacker` so the
  allowlisted receiver URL passes Gogs' delivery-time localCIDR check.

## Seed (CVE-2022-1285)

A webhook whose payload URL points directly at the internal canary is created via
the API (the API `CreateHook` endpoint performs no localCIDR validation). On
0.12.7 delivery performs no re-check either, so the hook is delivered into the
internal network and the canary's flag response is captured in the delivery
record (visible on `/repos/{owner}/{repo}/settings/hooks/{id}`). On 0.14.2 the
delivery re-check refuses the canary URL before any request is sent.

## Residual (CVE-2026-47267)

A webhook whose payload URL points at the allowlisted attacker receiver. On
0.14.2 the delivery-time check passes (allowlist), the client follows the 302
redirect (Go `http.Client` default) and the internal canary response is captured
in the delivery record. On 0.14.3 `SetCheckRedirect` refuses all redirects and
the record shows `Delivery: ... refusing to follow webhook redirect ...`.

## Flag

Planted by compose into `/flag.txt` in the canary container from `$PCB_FLAG`
(environment, not app code). The flag token appears in the Gogs webhook
delivery-history page only when the internal service was actually reached.

## Gate

Four edges verified in real Docker: seed@V0 reaches (flag in delivery body),
seed@V1 blocked ("implicitly blocked"), residual@V1 reaches (flag), residual@V2
blocked ("refusing to follow webhook redirect"). See repro.log.
