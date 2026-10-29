# craft-cms-cve-2026-27129

Craft CMS — CVE-2025-68437 -> CVE-2026-27129 (the fix validates hosts with PHP
`gethostbyname()`, which is IPv4-ONLY: an AAAA-only hostname comes back as the
unresolved string, defeating the IPv4 metadata blocklist while Guzzle/libcurl
connects over IPv6; SSRF, CWE-918). **Genuine incomplete fix; gate passed on real
Docker over EXTERNAL HTTP.**

Incomplete-fix writeup: [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md).

REAL Craft CMS booted per version via composer (`craftcms/cms` pinned
5.8.20 / 5.8.22 / 5.8.23, versions verified in-container) + real MariaDB 11 +
`php craft install`; the attacker drives Craft's OWN GraphQL
`save_pcbvol_Asset(_file:{url})` mutation over EXTERNAL HTTP
(`POST /index.php?p=actions/graphql/api`), with the public GraphQL schema opened
via Craft's own service layer (`pcb_setup.php`). Distinct sibling of
PCBV2-0090 (DNS-rebinding TOCTOU on the same sink): here the network is
DUAL-STACK (`192.0.0.0/24` + `fd00:ec2::/64`, `enable_ipv6`) with a static
A/AAAA DNS sidecar (`192.0.0.53`) — `seed.pcb.test` A=192.0.0.192,
`host6.pcb.test` A=NODATA + AAAA=`fd00:ec2::254`. The canary is dual-stack
(192.0.0.192 Oracle-metadata IPv4 AND fd00:ec2::254 AWS-IMDS-style IPv6, no host
port) serving `${PCB_FLAG}` on both stacks; the fetched body is stored as an
asset and read back.

`patch_real.diff` is the CVE-2025-68437 fix (commit `013db63…`, 5.8.21; IPv4
blocklist added 5.8.22, `src/gql/resolvers/mutations/Asset.php
validateHostname`): `gethostbyname($host)` against the cloud-metadata IPv4
blocklist (169.254.169.254/170.2, 100.100.100.200, 192.0.0.192). Incomplete —
`gethostbyname()` never consults AAAA records: for an AAAA-only host it returns
the HOSTNAME STRING, which is never in the numeric blocklist, so the guard passes
and libcurl's `getaddrinfo` connects over IPv6. GHSA-v2gc-rm6g-wrw9 (case.json
`evidence.incomplete_fix_quote`): "causing the blocklist comparison to always
fail and completely bypassing SSRF protection." The 5.8.23 fix (commit
`2825388b…`) adds an IPv6 metadata PREFIX blocklist (fd00:ec2::, fd20:ce::, ::1,
fe80:, ::ffff:) to `validateIp()` on the request-time `ON_STATS` primary_ip.

- **V0 = 5.8.20** (`:39530`) — no host validation; the IPv4 seed host is fetched
  -> flag (repro.log/audit: seed flag@v0).
- **V1 = 5.8.22** (`:39531`, target) — the 68437 fix BLOCKS the IPv4 seed
  ("contains an invalid hostname"), but `host6.pcb.test` passes: primitive check
  `gethostbyname('host6.pcb.test')` returns the hostname string; Guzzle connects
  to `[fd00:ec2::254]` (`primary_ip=fd00:ec2::254`) -> flag. Incomplete fix.
- **V2 = 5.8.23** (`:39532`, 27129 fix) — `ON_STATS validateIp` rejects the
  connected `fd00:ec2::254` by the `fd00:ec2::` prefix -> "resolves to an invalid
  IP address"; the seed's real IPv4 connect is also rejected (blocked@v2).

- **Original trigger**: GraphQL `save_pcbvol_Asset` with
  `url: "http://seed.pcb.test/flag"` (A -> IPv4 metadata canary;
  `poc/original_poc.py` `URL`).
- **Residual trigger**: same mutation with
  `url: "http://host6.pcb.test/flag"` (AAAA-only -> IPv6 metadata canary;
  `_heldout/bypass_poc.py` `URL`).

Run: `python3 oracle.py --gate` (gate 2026-07-17 on real Docker/OrbStack: seed
flag@v0 / seed blocked@v1 / residual flag@v1 / residual blocked@v2; passed=true).
See `repro.log` and `case.json`.

> NOTE: same stale-file situation as PCBV2-0090 — the root `entrypoint.sh` still
> `exec php -S ... /app/harness.php` from the RETIRED faithful-core harness (kept
> per the no-rm policy, no longer built or served); the real boot is
> `craft-entrypoint.sh` via the Dockerfile.
