# cockpit-cve-2018-9302

Cockpit (getcockpit CMS) — CVE-2017-14611 -> CVE-2018-9302 (the 14611 fix
allow-lists the SCHEME (`^https?://`) but never the DESTINATION, so plain
`http://` SSRF to intranet hosts survives; CWE-918). **Genuine incomplete fix;
gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real upstream Cockpit at pinned `agentejo/cockpit` commits (V0 `a5fb51cb` /
V1 `0711d4f9`) on `php:7.1-apache`, serving the product's own SSRF proxy
`/assets/lib/fuc.js.php?url=` (curl with `CURLOPT_FOLLOWLOCATION=1`, body returned
to the caller; same-host guard satisfied via `Host`/`Referer: 127.0.0.1`). Two
per-run `${PCB_FLAG}` canaries, both unreachable normally: `/flag.txt` on the
Cockpit container (outside DocumentRoot — plain `GET /flag.txt` is 404) read by
the `file://` seed, and `/flagdata/flag.txt` on the internal-only `intranet`
sidecar (php `-S`, NO host port — reachable only server-side) read by the http
residual.

`patch_real.diff` is the CVE-2017-14611 first-fix
(`a5fb51cb..0711d4f9`, `assets/lib/fuc.js.php`): adds
`filter_var(FILTER_VALIDATE_URL)` + `if (!preg_match('#^http(|s)\://#', $url))
{ 403 }`. Incomplete — it restricts the scheme but not the destination; no
private-range/loopback predicate and no follow redirect. NVD (case.json
`evidence.incomplete_fix_quote`): "It stems from an incomplete fix for
CVE-2017-14611. The CVE-2017-14611 fix restricts the URL scheme to http(s) but
not the destination, so http:// SSRF to intranet hosts remains possible."

- **V0 = pre-14611** (`cockpit@a5fb51cb`, `:39001`) — any scheme accepted;
  `url=file:///flag.txt` reads the canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = 14611-patched** (`cockpit@0711d4f9`, `:39002`, target) — the 14611 fix
  BLOCKS the `file://` seed (HTTP 403), but `url=http://intranet/flag.txt` passes
  the scheme guard and the server-side fetch returns the sidecar's flag
  (HTTP 200 CANARY-HIT). Incomplete fix. (The published PoC's
  open-redirect -> `file://` bounce is NOT followable on modern libcurl >= 7.19.4
  — `CURLOPT_REDIR_PROTOCOLS` excludes file, verified on 7.64.0 per repro.log —
  so the direct intranet-http read is the deterministic gated residual.)
- **V2 = proxy removed** (`cockpit@279e6690`, `:39003`, added by the 2026-08-02
  re-gate) — upstream removed `assets/lib/fuc.js.php` entirely -> bypass 404, no
  flag (case.json `status.frozen_2026-08-02`).

- **Original trigger**: `GET /assets/lib/fuc.js.php?url=file:///flag.txt`
  (`poc/original_poc.py` `URL = "file:///flag.txt"`).
- **Residual trigger**: `GET /assets/lib/fuc.js.php?url=http://intranet/flag.txt`
  (`_heldout/bypass_poc.py` `URL`; `intranet` is internal-only).
  Controls: missing Referer -> 401; plain `GET /flag.txt` -> 404.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-10, gate flag `PCBFLAG_103bf9aff467ec63a18d19585308e661`: v0 seed
200 HIT / v1 seed 403 / v1 residual 200 HIT; passed=True; v2 closure 2026-08-02).

> NOTE: case.json `versions.v2_fixed` says "n/a" ("upstream shipped no clean
> scheme-independent destination filter ... e028770c only fixed the
> missing-HTTP_HOST case") while `status.frozen_2026-08-02` and the compose file
> add a V2 (`cockpit@279e6690`, port 39003) whose fix is ENDPOINT REMOVAL — the
> two fields were not reconciled after the 2026-08-02 re-gate.
