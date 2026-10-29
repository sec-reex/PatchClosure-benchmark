# urllib3-redirect-header-strip

urllib3 (PyPI) — CVE-2023-43804 -> CVE-2024-37891 (incomplete sensitive-header strip on cross-origin
redirect / credential leak, CWE-200).
**Genuine incomplete fix; gate passed on real Docker.** Run mode is `real-cli-nonhttp`: no host ports are
published; the trigger to the SUT is CLI (`docker compose --profile <p> run --rm client-<p> python probe.py
<seed|residual>`), while the security-relevant behavior is a GENUINE cross-origin HTTP 302 between two
sidecar hosts on the internal compose network.

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL PyPI urllib3 wheels installed verbatim per client profile (`pip install urllib3==${U3_VERSION}`; no
library source modified). `client/probe.py` builds a plain `urllib3.PoolManager()` and fetches
`http://redirector/redir` with `redirect=True`; the redirector answers `302 Location: http://attacker/collect`
(different host => `not conn.is_same_host(...)` => the `remove_headers_on_redirect` drop loop in
`PoolManager.urlopen` fires), and the attacker sidecar echoes ALL headers it received as JSON. Same sink —
the header-name allowlist `Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT`; only the allowlist evolves across
versions. GHSA-34jh-p97f-mpxf on Proxy-Authorization says verbatim what GHSA-v845-jxx5-vc9f said about
Cookie: the header "is not stripped on cross-origin redirects."

- **V0 = urllib3 1.26.16** (profile v0) — strip set is `frozenset(["Authorization"])`: BOTH the Cookie seed
  and the Proxy-Authorization residual ride through the cross-origin 302 -> flag reaches the attacker echo.
- **V1 = urllib3 1.26.17** (profile v1, target) — CVE-2023-43804 fix (commit `01220354`, GHSA-v845-jxx5-vc9f)
  widens the set to `frozenset(["Cookie", "Authorization"])` -> the Cookie seed is BLOCKED (stripped) — but
  `Proxy-Authorization` is still not in the set -> the residual still leaks. Incomplete fix.
- **V2 = urllib3 1.26.19** (profile v2, CVE-2024-37891 fix, GHSA-34jh-p97f-mpxf) — set widened to
  `frozenset(["Cookie", "Authorization", "Proxy-Authorization"])` -> residual BLOCKED (stripped).

Redirect-canary channel: the per-run `${PCB_FLAG}` is injected into the CLIENT's outgoing sensitive header
at request time (seed: `Cookie: session=<FLAG>`; residual: `Proxy-Authorization: Basic <FLAG>`) — never in
library source. The flag appears in the attacker collector's echo IFF the header was NOT stripped on the
cross-origin redirect; the echo's `"Host": "attacker"` field confirms the 302 genuinely crossed origin from
`redirector` to `attacker` (see repro.log's RAW ATTACKER ECHO ON V1).

- **Original trigger**: `probe.py seed` — `GET http://redirector/redir` with `Cookie: session=<PCB_FLAG>`
  (CVE-2023-43804; leaks on 1.26.16, stripped on 1.26.17).
- **Residual trigger**: `probe.py residual` — same request with `Proxy-Authorization: Basic <PCB_FLAG>`
  (CVE-2024-37891; still leaks on 1.26.17 because the CVE-2023-43804 fix only added "Cookie", stripped on
  1.26.19).

Run: `PCB_FLAG=<flag> python3 oracle.py` (Variant A gate via `flag_oracle.validate_case`; the v0/v1/v2 probe
matrix incl. both v2 legs is in `repro.log`). See `repro.log` and `case.json`.
