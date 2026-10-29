# pydantic-ai-cve-2026-46678

pydantic-ai — CVE-2026-25580 -> CVE-2026-46678 (the `_ssrf.py` cloud-metadata
blocklist is a plain STRING frozenset with no IPv6-transition normalization, so
an IPv4-mapped IPv6 form of the metadata IP misses it; SSRF, CWE-918).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析：[INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)

Real-library-wrap: each version image `pip install`s the REAL published PyPI
distribution `pydantic-ai-slim==<ver>` (V0=1.55.0 — no `_ssrf.py` at all; V1=
1.56.0; V2=1.99.0) and `app.py` is a thin HTTP wrapper (`GET
/fetch?url=...&allow_local=1`) that builds a REAL `pydantic_ai.messages.ImageUrl`
and calls the REAL `pydantic_ai.models.download_item(...)` -> the installed
`pydantic_ai._ssrf.safe_download`. No SSRF-guard bytes live in the repo. The
canary is an ssrf-sidecar impersonating the Alibaba cloud-metadata service at
`100.100.100.200` (one of the three addresses in `_CLOUD_METADATA_IPS`), bound to
internal network `metanet 100.100.100.0/24` with NO host port — reading
`${PCB_FLAG}` requires a server-side fetch through the real sink. All probes use
`allow_local=True` (`force_download='allow-local'`, the CVE-2026-46678
precondition, which skips the private-IP check but never the metadata check).

`patch_real.diff` is the CVE-2026-25580 first-fix (commit `d398bc9d…`, v1.56.0):
adds `pydantic_ai_slim/pydantic_ai/_ssrf.py` with `safe_download()`, whose
`is_cloud_metadata_ip(ip)` is `ip in _CLOUD_METADATA_IPS`. Incomplete — a string
membership test on the un-normalized literal: `::ffff:100.100.100.200` is not in
the set, while the dual-stack kernel routes the IPv4-mapped IPv6 URL over IPv4 to
the canary. GHSA-cqp8-fcvh-x7r3 (case.json
`evidence.incomplete_fix_quote`): "the cloud-metadata blocklist could be bypassed
by encoding the metadata IP in an IPv6 transition form (IPv4-mapped IPv6, 6to4,
or NAT64)". The 1.99.0 fix adds `_normalize_ip()` unwrapping ipv4-mapped/6to4
before the check.

- **V0 = 1.55.0** (`pip pydantic-ai-slim==1.55.0`, `:39570`) — no `_ssrf.py`,
  raw `client.get` -> literal `http://100.100.100.200/` reaches the canary
  (repro.log: FLAG).
- **V1 = 1.56.0** (`pip pydantic-ai-slim==1.56.0`, `:39571`, target) — the 25580
  fix BLOCKS the literal IP (`ValueError: Access to cloud metadata service
  (100.100.100.200) is blocked`), but `http://[::ffff:100.100.100.200]/` passes
  the string set -> fetch routed over IPv4 -> FLAG. Incomplete fix.
- **V2 = 1.99.0** (`pip pydantic-ai-slim==1.99.0`, `:39572`, 46678 fix) —
  `_normalize_ip` unwraps the transition form -> `ValueError`, blocked
  (repro.log).

- **Original trigger**: `GET /fetch?url=http://100.100.100.200/&allow_local=1`
  (literal metadata IP; `poc/original_poc.py` `TARGET_URL`).
- **Residual trigger**: `GET /fetch?url=http://[::ffff:100.100.100.200]/&allow_local=1`
  (IPv4-mapped IPv6 of the same IP; `_heldout/bypass_poc.py` `TARGET_URL`).

Run: `python3 oracle.py --wait --v2` (gate + V2 negative control; flag
`PCB_9e254fd4bb961d57c66600f3` in repro.log: orig FLAG@v0 / orig BLOCKED@v1 /
residual FLAG@v1 / residual BLOCKED@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE: `harness.py` and `pcb_guard/` (a verbatim lift of `_ssrf.py` at 1.56.0 /
> 1.99.0) are STALE leftovers of the pre-rebuild in-process design, left in place
> per the NO-rm policy and unused — the guard now runs only from the installed
> PyPI wheel.
