# activitypub-federation-rust-unspecified

activitypub_federation — CVE-2025-25194 → CVE-2026-33693 (SSRF resolve-then-denylist coverage gap: `0.0.0.0`/`is_unspecified` not rejected, CWE-918).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (2026-07-15, Docker 29.4.0 arm64 — see `repro.log`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL axum service (`service/src/main.rs`) depends on the REAL published crates.io
`activitypub_federation` crate — one exact version per profile via Dockerfile ARG `AP_VER`
(build logs confirm `Compiling activitypub_federation v0.6.1 / v0.7.0-beta.8 / v0.7.0-beta.9`).
`POST /fetch {"url": ...}` calls the crate's REAL `fetch_object_http::<(), RemoteObject>`, whose OWN
`FederationConfig::verify_url_valid` SSRF guard resolves the host via tokio `lookup_host` and decides
block/fetch BEFORE the outbound GET (config `debug=false`, `allow_http_urls=true`, instance domain
`svc.pcb`). Attack domains resolve via `/etc/hosts` (crate rejects IP-literal URLs, so probes use
DOMAINS): `original-target.pcb`→127.0.0.1 (seed), `residual-target.pcb`→0.0.0.0 (residual),
`residual6-target.pcb`→::ffff:0.0.0.0 (secondary v6-mapped residual). The canary lives only in a
co-located loopback sidecar (`service/src/bin/sidecar.rs`, binds 0.0.0.0:80 in the SAME container, no
host port) answering as a minimal ActivityPub object; the service process is started `env -u PCB_FLAG`,
so a flag in `flag_body` proves a genuine loopback SSRF, not env leakage.

- **V0 = 0.6.1** (`:39770`) — `verify_url_valid` does NO IP resolution at all → seed (127.0.0.1)
  fetches the sidecar, `flag_body=<FLAG>`. Seed and residual both open.
- **V1 = 0.7.0-beta.8** (`:39771`, target) — CVE-2025-25194 guard (first added by #134 in 0.6.2,
  commit `4ad668cc10`) inline in `src/config.rs`: IPv4 rejects
  `is_private||is_link_local||is_loopback||is_multicast` → seed 127.0.0.1 BLOCKED
  (`"Localhost is only allowed in debug mode"`). But `0.0.0.0` is false on ALL four predicates —
  `is_unspecified()` is never checked → residual passes the guard, the OS routes 0.0.0.0 → loopback
  sidecar, `flag_body=<FLAG>`. Incomplete fix (same on `::ffff:0.0.0.0` — no `to_ipv4_mapped()`).
- **V2 = 0.7.0-beta.9** (`:39772`, CVE-2026-33693 fix commit `4ae8532b17` #162) — `src/utils.rs
  v4_is_invalid()` now also rejects `is_unspecified()`+`is_broadcast()`; IPv6 inherits via
  `to_ipv4_mapped()` → residual BLOCKED with the crate's own
  `"...points to local IP address... DANGER_FEDERATION_ALLOW_LOCAL_IP"` error (negative control).

- **Original trigger**: `POST /fetch {"url": "http://original-target.pcb/flag"}` (hosts → 127.0.0.1)
  through the real `fetch_object_http` → `verify_url_valid` loopback sink.
- **Residual trigger**: `POST /fetch {"url": "http://residual-target.pcb/flag"}` (hosts → 0.0.0.0,
  all four V1 predicates false, OS routes unspecified → 127.0.0.1 sidecar); secondary
  `http://residual6-target.pcb/flag` (::ffff:0.0.0.0) inherits the gap through the IPv6 branch.

Run: `python3 oracle.py --gate` (or `--wait`; `--probe orig|bypass|bypass6`; needs `PCB_FLAG`). See `repro.log` and `case.json`.

> NOTE: `patch_real.diff`'s header labels commit `f47fe582` as the "CVE-2025-25194 fix", but
> `patch.diff`'s GUARD LINEAGE note (and `case.json`) attribute the 25194 mitigation to #134 /
> `4ad668cc10` (first in 0.6.2) and identify `f47fe582` as #161 "Better IP check" — the refactor of
> the inline guard into `src/utils.rs::v4_is_invalid` that STILL omits `is_unspecified()`. Substance
> is consistent (the guard present in V1 omits unspecified; #162 adds it), but the header label is off.

> NOTE: `_heldout/bypass_poc.py` is claimed as held out in `case.json` (`held_out`), but an identical
> copy exists at `poc/bypass_poc.py` (`diff` reports the two files SAME).
