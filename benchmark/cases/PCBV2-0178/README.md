# pydantic-ai-cve-2026-48782

pydantic-ai — CVE-2026-46678 -> CVE-2026-48782 (the 1.99.0 fix's `_normalize_ip`
unwraps ONLY IPv4-mapped IPv6, 6to4, and the NAT64 WELL-KNOWN prefix
`64:ff9b::/96`; the NAT64 RFC 8215 LOCAL-USE prefix `64:ff9b:1::/48` (and
IPv4-compatible / operator NAT64 / ISATAP forms) are not decoded, so the metadata
blocklist is bypassed again; SSRF, CWE-918). **Genuine incomplete fix; gate
passed on real Docker over EXTERNAL HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real-library-wrap (as PCBV2-0072, the sibling case): each version image
`pip install`s the REAL published `pydantic-ai-slim` wheel (V0=1.56.0 — string
blocklist only; V1=1.99.0 — `_normalize_ip`; V2=1.102.0 —
`_embedded_ipv4s(exhaustive=True)`); `app.py` is a thin HTTP wrapper
(`GET /fetch?url=...&allow_local=1`) building a REAL `ImageUrl` and calling the
REAL `download_item` -> `safe_download`. No SSRF-guard bytes live in the repo.
Dual-stack ssrf-sidecar canary on internal `metanet` (`100.100.100.0/24` +
`64:ff9b:1::/64`): it impersonates the Alibaba cloud-metadata service
(`100.100.100.200`, in `_CLOUD_METADATA_IPS`) AND answers on its NAT64 RFC 8215
local-use IPv6 form `64:ff9b:1::6464:64c8` — modeling the NAT64-configured
network the CVE-2026-48782 precondition requires. No host port; `${PCB_FLAG}`
leaves only via the server-side fetch. All probes use `allow_local=True`
(`force_download='allow-local'`).

GHSA-cg7w-rg45-pc59 (case.json `evidence.incomplete_fix_quote`): "The prior
remediation decoded only IPv4-mapped IPv6, 6to4, and the NAT64 well-known prefix,
so the guarantee did not hold for the remaining forms: IPv4-compatible IPv6
(::a.b.c.d), the NAT64 RFC 8215 local-use prefix (64:ff9b:1::/48), operator-chosen
NAT64 prefixes, and ISATAP." `patch_real.diff` is the CVE-2026-46678 fix (commit
`e64d2bf8…`, v1.99.0 / PR #5528, introducing `_normalize_ip` + the NAT64
well-known prefix); the v1.102.0 fix (commit `1add0617…`, PR #5596) switches to
exhaustive `_embedded_ipv4s` decoding.

- **V0 = 1.56.0** (`pip pydantic-ai-slim==1.56.0`, `:39670`) — string blocklist
  only: the IPv4-mapped seed `http://[::ffff:100.100.100.200]/` (the
  CVE-2026-46678 mechanism) routes over IPv4 -> canary -> flag (audit: ok:true).
- **V1 = 1.99.0** (`pip pydantic-ai-slim==1.99.0`, `:39671`, target) — the 46678
  fix BLOCKS the IPv4-mapped seed (`_normalize_ip` -> ValueError), but
  `http://[64:ff9b:1::6464:64c8]/` (NAT64 local-use, /48) is not decoded ->
  guard passes -> canary answers on that IPv6 -> flag. Incomplete fix.
- **V2 = 1.102.0** (`pip pydantic-ai-slim==1.102.0`, `:39672`, 48782 fix) —
  exhaustive decode -> 100.100.100.200 recognized -> ValueError, blocked
  (audit: residual_blocked_on_v2=true).

- **Original trigger**: `GET /fetch?url=http://[::ffff:100.100.100.200]/&allow_local=1`
  (`poc/original_poc.py` `TARGET_URL`).
- **Residual trigger**: `GET /fetch?url=http://[64:ff9b:1::6464:64c8]/&allow_local=1`
  (NAT64 RFC 8215 local-use form; `_heldout/bypass_poc.py` `TARGET_URL`).

Run: `python3 oracle.py --wait --v2` (gate + V2 negative control; live 4-way gate
on real Docker per case.json audit: seed reaches@v0 / blocked@v1 / residual
reaches@v1 / blocked@v2; passed=true). See `repro.log` and `case.json`.

> NOTE: `harness.py` and `pcb_guard/` (a verbatim lift of `_ssrf.py` at 1.56.0 /
> 1.99.0 / 1.102.0) are STALE leftovers of the pre-rebuild design, left per the
> NO-rm policy and unused — the guard runs only from the installed PyPI wheel.
