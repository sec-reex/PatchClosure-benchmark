# craft-cms-cve-2026-27127

Craft CMS — CVE-2025-68437 -> CVE-2026-27127 (the fix resolves the host itself
with `gethostbyname` + an IP blocklist, but the Guzzle fetch re-resolves the same
hostname — a check-vs-fetch DNS TOCTOU enabling rebinding; SSRF, CWE-367/918).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

Incomplete-fix writeup: [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md).

REAL Craft CMS booted per version via composer (`craftcms/cms` pinned
5.8.20 / 5.8.22 / 5.8.23, confirmed at runtime via `Composer\InstalledVersions`)
+ real MariaDB 11 + `php craft install`; the attacker drives Craft's OWN GraphQL
`save_pcbvol_Asset(_file:{url})` mutation over EXTERNAL HTTP
(`POST /index.php?p=actions/graphql/api`); the fetched body is stored as an asset
and read back over HTTP. A deterministic rebinding cluster on `192.0.0.0/24`:
canary `192.0.0.192` (a cloud-metadata IP in Craft's blocklist, no host port)
serving `${PCB_FLAG}`; decoy `192.0.0.50` (non-blocklisted, no flag); DNS
`192.0.0.53` (`dns_server.py`) answering `rebind.pcb.test` with alternating
A-records (odd query = CHECK -> decoy, even = FETCH -> canary) — parity confirmed
in the DNS sidecar log. MySQL uses a static IP so it never touches the resolver.

`patch_real.diff` is the CVE-2025-68437 fix (commit `013db636…`, 5.8.21, later
extended with the IP blocklist in 5.8.22, `src/gql/resolvers/mutations/
Asset.php handleUpload`): `validateHostname($url)` requires
`FILTER_VALIDATE_DOMAIN`, rejects IP literals and metadata hostnames, then
`gethostbyname($host)` against a cloud-metadata blocklist. Incomplete — the CHECK
lookup is separate from the FETCH: `createGuzzleClient()->request('GET', $url)`
makes libcurl resolve the hostname a second time. GHSA-gp2f-7wcm-5fhx (case.json
`evidence.incomplete_fix_quote`): "This is a bypass of the security fix for
CVE-2025-68437 (GHSA-x27p-wfqw-hfcc) that allows access to all blocked IPs." The
5.8.23 fix (commit `a4cf3fb…`) drops the separate resolution and validates the
ACTUAL connected IP via `RequestOptions::ON_STATS => validateIp(primary_ip)`.

- **V0 = 5.8.20** (`:39520`) — no host validation; `seed.pcb.test` (always ->
  192.0.0.192) is fetched -> flag (repro.log: seed FLAG@v0).
- **V1 = 5.8.22** (`:39521`, target) — the 68437 fix BLOCKS the static seed
  (`gethostbyname` returns the blocklisted 192.0.0.192 -> "contains an invalid
  hostname"), but for `rebind.pcb.test` the CHECK resolves to the decoy
  192.0.0.50 (passes) while the FETCH resolves to the canary -> FLAG. Incomplete
  fix (exactly 2 A-queries per request observed).
- **V2 = 5.8.23** (`:39522`, 27127 fix) — only the fetch lookup happens (1
  A-query), and `ON_STATS validateIp` rejects the canary IP -> "resolves to an
  invalid IP address", blocked.

- **Original trigger**: GraphQL `save_pcbvol_Asset` with
  `url: "http://seed.pcb.test/flag"` (static canary host;
  `poc/original_poc.py` `URL`).
- **Residual trigger**: same mutation with
  `url: "http://rebind.pcb.test/flag"` (rebinding hostname;
  `_heldout/bypass_poc.py` `URL`).

Run: `python3 oracle.py --gate` (gate 2026-07-16..17, flag
`PCBFLAG_65b473d672b79eb35de7dd6fecba413c`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE: the root `entrypoint.sh` is a STALE leftover of the pre-rebuild
> faithful-core harness (`exec php -S ... /app/harness.php`); the audit says both
> `harness.php` and the old `entrypoint.sh` were retained per the NO-rm policy,
> but `harness.php` is absent from the directory. The real boot is
> `craft-entrypoint.sh` referenced by the Dockerfile.
