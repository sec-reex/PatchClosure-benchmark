# follow-redirects-header-strip

follow-redirects (npm) — CVE-2022-0536 → CVE-2024-28849 (sensitive-header strip gap on redirect:
scheme-downgrade fixed, `Proxy-Authorization` left out of the strip regex, CWE-200 credential leak).
**Genuine incomplete fix; gate passed on real Docker (`passed: TRUE` in `repro.log`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL npm client library: each profile builds `node:20-slim` + `npm i follow-redirects@<ver>`
(1.14.7 / 1.14.8 / 1.15.6) and a node CLI probe (`client/probe.mjs`, run via `docker compose run`)
performs a GENUINE cross-container HTTP redirect chain against real node sidecars
(`servers/victim.mjs` https:443+http:80, `servers/redirector.mjs` http:80, `servers/attacker.mjs`
http:80 collector that echoes the headers it actually received). No inbound HTTP request drives the
SUT and NO host ports are published — the probes run on the internal `pcbnet` network only — but real
HTTP rides the wire and the flag is observed in the attacker/victim collector's echo. The per-run
`${PCB_FLAG}` rides in the client's sensitive header (seed: `Authorization`; residual:
`Proxy-Authorization`); flag in the echo == the header was NOT stripped.

- **V0 = follow-redirects 1.14.7** (profile v0) — `_processResponse()` strips
  `/^(?:authorization|cookie)$/i` ONLY when redirecting to another HOST; no scheme check → seed's
  https→http same-host downgrade leaks `Authorization`, and `Proxy-Authorization` is never stripped.
  Both seed and residual LEAK.
- **V1 = follow-redirects 1.14.8** (target; CVE-2022-0536 fix commit `62e546a9`) — the check widens to
  `redirectUrlParts.protocol !== currentUrlParts.protocol || !isSameOrSubdomain(...)` → the seed's
  scheme downgrade now fires the strip → `SEED_FLAG_LEAKED: false`, BLOCKED. But the strip regex
  stays `/^(?:authorization|cookie)$/i` — `Proxy-Authorization` (also credentials) is NOT in the set →
  it still crosses a genuine cross-domain 302 (`RESIDUAL_FLAG_LEAKED: true`). Incomplete fix.
- **V2 = follow-redirects 1.15.6** (CVE-2024-28849 fix) — regex widened to
  `/^(?:(?:proxy-)?authorization|cookie)$/i` → residual BLOCKED (`RESIDUAL_FLAG_LEAKED: false`).

- **Original trigger**: `node probe.mjs seed` — GET `https://victim/redir` with
  `Authorization: Basic ${PCB_FLAG}`; victim answers `302 Location: http://victim/collect`
  (SAME host, scheme downgrade https→http); flag reaches the victim:80 collector echo iff unstripped.
- **Residual trigger**: `node probe.mjs residual` — GET `http://redirector/redir` with
  `Proxy-Authorization: Basic ${PCB_FLAG}`; redirector answers `302 Location: http://attacker/collect`
  (DIFFERENT service hostname → genuinely cross-domain, so the strip path fires — but the header set
  is short); flag reaches the attacker collector echo on V1.

Run: `python3 oracle.py` (no CLI flags; runs `flag_oracle.validate_case` over v0/v1/bypass). See `repro.log` and `case.json`.

> NOTE: `_heldout/bypass_poc.py` is claimed as held out in `case.json` (`held_out`), but an identical
> copy exists at `poc/bypass_poc.py` (`diff` reports the two files SAME).
