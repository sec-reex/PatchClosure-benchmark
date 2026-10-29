# faraday-cve-2026-33637

faraday — CVE-2026-25765 -> CVE-2026-33637 (Protocol-relative URL host-override SSRF, CWE-918).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

A REAL destination-pinned proxy service (`app.rb` ROLE=server, `GET /fetch?to=<target>&mode=<string|uri>`)
runs the REAL, unmodified published rubygems `faraday` (installed per-image via
`gem install faraday -v <ver>`) and builds `Faraday.new(url:'http://trusted-base.pcb').get(<user
target>)` — the sink is `Faraday::Connection#build_exclusive_url` (lib/faraday/connection.rb) — and
echoes the fetched upstream body. This mirrors how faraday is routinely used: ONE connection with a
FIXED base URL carrying connection-scoped Authorization, user supplies only the request target. Same
sink across all three versions.

- **V0 = faraday 2.14.0** (server `:39610`) — the `./`-prefix guard only fires for targets NOT
  starting with `'http://','https://','/','./','../'`; a protocol-relative `//attacker.pcb/flag`
  starts with `/` -> guard never fires -> `URI#merge` takes the `//authority` -> base host OVERRIDDEN
  -> the seed reaches the flag sidecar.
- **V1 = faraday 2.14.1** (server `:39611`, target) — CVE-2026-25765 fix adds
  `|| url.start_with?('//')` -> a STRING `//host` is `./`-prefixed and stays on trusted-base.pcb ->
  the seed is BLOCKED. INCOMPLETE: the guard is gated on `url.respond_to?(:start_with?)`, and a URI
  OBJECT does NOT respond to `start_with?` -> `URI('//attacker.pcb/flag')` skips the guard entirely,
  `URI#merge` still takes `//attacker.pcb` -> the residual REACHES the flag sidecar. Incomplete fix.
- **V2 = faraday 2.14.2** (server `:39612`, -33637 fix) — inserts
  `url = url.to_s if url.respond_to?(:host)` BEFORE the guard -> a URI object is coerced to its
  String form, the `//`-prefix guard fires -> stays on the base host -> residual BLOCKED.

SSRF-sidecar channel: the INTERNAL-only sidecar `attacker.pcb` (ROLE=attacker, distinct network
alias, listens :80, NO published host port) serves `${PCB_FLAG}` on any path; the configured base
host `trusted-base.pcb` (ROLE=base) serves a benign `TRUSTED-BASE OK ...` body on every path. The
flag token can appear in the server's echoed body ONLY if the user target overrode the fixed base
host. Detection = flag-token substring in the fetched upstream body. A plain relative target
(`/status`) merges onto the base URL on all versions, so the base is not trivially bypassable.

- **Original trigger**: `mode=string`, `to=//attacker.pcb/flag` (protocol-relative STRING) —
  blocked by 2.14.1's `|| url.start_with?('//')` (CVE-2026-25765 / GHSA-33mh-2634-fwr2 fix).
- **Residual trigger**: `mode=uri`, `to=//attacker.pcb/flag` — the app parses the user input into a
  `URI(...)` object (the common "validate the URL first" pattern) before fetching; a URI object does
  not `respond_to?(:start_with?)`, so 2.14.1's guard is skipped; closed by 2.14.2's `url.to_s`
  coercion (CVE-2026-33637 / GHSA-5rv5-xj5j-3484).

Run: `PCB_FLAG=<tok> python3 oracle.py --wait`. See `repro.log` and `case.json`.

> NOTE (case.json `audit.version_note`): the GitHub advisory GHSA-5rv5-xj5j-3484 lists
> "Patched: 2.14.2" while the RubySec metadata lists 2.14.3; `lib/faraday/connection.rb` is
> BYTE-IDENTICAL between 2.14.2 and 2.14.3 (verified by gem-source diff), so V2 is pinned to
> 2.14.2 = the first fixed release (tightest V1->V2 incomplete-fix delta).
