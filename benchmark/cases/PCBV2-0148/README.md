# netmask-octal-ssrf

netmask (npm, rs/node-netmask) — CVE-2021-28918 -> CVE-2021-29418 (the 2.0.0 fix
makes leading-0 octets parse as OCTAL — closing the octal loopback `0177.0.0.1`
bypass — but its hex test is `byte[1]==='x' || byte[1]==='x'`, a verbatim typo
where the second arm should be `'X'`, so UPPERCASE-hex `0X7f.0.0.1` falls to
`parseInt('0X7f',8)=0` and is classified as public `0.0.0.1`; SSRF / IP-ACL
bypass, CWE-918). **Genuine incomplete fix; gate passed on real Docker over
EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: the REAL npm `netmask` package installed per-version via npm
aliases (`netmask@1.0.6` = V0 / `2.0.0` = V1 / `2.0.1` = V2) inside a node:20-slim
HTTP fetcher whose SSRF guard is `Netmask(block).contains(rawHost)` over the
private-range denylist {127/8, 10/8, 172.16/12, 192.168/16, 169.254/16}
(`0.0.0.0/8` intentionally omitted — the common real-world denylist gap the
residual exploits). The host is read RAW from `?host=` (no `new URL`/`url.parse`,
which would canonicalise the encoding); the outbound sink is Node native fetch
(undici). ssrf-sidecar canary: a loopback flag server bound to `127.0.0.1:80`
inside each container serves `${PCB_FLAG}` — both crafted forms route to loopback
at connect time, so the flag is retrievable only via a fetch the version's
netmask guard ADMITS.

NVD (case.json `evidence.incomplete_fix_quote`): "netmask before 2.0.1 mishandles
certain unexpected characters in an IP address string ... allows attackers to
bypass access control based on IP addresses. This issue exists because of an
incomplete fix for CVE-2021-28918." `patch_real.diff` is the CVE-2021-28918 fix
(commit `4678fd840ad0b4730dbad2d415712c0782e886cc`, 2.0.0, `lib/netmask.coffee`
ip2long octal branch). The CVE-2021-29418 fix (2.0.1) rewrites ip2long as a
strict char scanner handling `0x`/`0X` and rejecting stray chars.

- **V0 = 1.0.6** (`:39570`) — leading zeros ignored: `0177.0.0.1` read as
  `177.0.0.1` (public) -> ADMIT -> fetch reaches loopback -> flag (repro.log:
  reaches).
- **V1 = 2.0.0** (`:39571`, target) — the 28918 fix BLOCKS the octal seed
  (`0177` -> octal 127 -> 127/8), but `0X7f.0.0.1`: the hex test never matches
  uppercase `X`, `parseInt('0X7f',8)=0` -> read as `0.0.0.1` (not in denylist) ->
  ADMIT -> fetch reaches loopback -> flag. Incomplete fix.
- **V2 = 2.0.1** (`:39572`, 29418 fix) — `0X7f` -> 127 -> 127/8 -> BLOCKED
  (repro.log; `_env_ready.v2` "not ready" via flag-probe is EXPECTED — v2
  correctly blocks the residual, it is the negative control).

- **Original trigger**: `GET /fetch?host=0177.0.0.1` (octal loopback;
  `poc/original_poc.py` candidate).
- **Residual trigger**: `GET /fetch?host=0X7f.0.0.1` (uppercase-hex loopback;
  `_heldout/bypass_poc.py` candidate).

Run: `python3 oracle.py --wait` (gate, Variant A + V2 negative: seed reaches@v0 /
seed blocked@v1 / residual reaches@v1 / residual blocked@v2; passed=true). See
`repro.log` and `case.json`.
