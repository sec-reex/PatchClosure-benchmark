# grafana-cve-2021-43813

Grafana — CVE-2021-43798 -> CVE-2021-43813 (the 8.3.1 fix clamps only the
`/public/plugins/:id/*` static-asset handler; the sibling markdown endpoint
`/api/plugins/:id/markdown/:name` still builds
`filepath.Join(plugin.PluginDir, name + ".md")` with NO containment check;
Path_Traversal; case.json records root_cause `Path_Traversal`, no CWE ID).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official Grafana images (`grafana/grafana-oss:8.3.0` / `8.3.1` / `8.3.2`,
recipe compose, `admin/admin` set via `GF_SECURITY_ADMIN_*` so the authenticated
markdown endpoint is reachable over HTTP basic auth). The compose entrypoint
writes `${PCB_FLAG}` to `/tmp/pcb_canary.md` — outside every Grafana-served root
(public/ assets and plugin dirs; a normal request 302s to login); the canary is a
`.md` with a lowercase basename because the 43813 handler appends `".md"` and has
a `ToLower` fallback. Read-exfil of a protected file, no gadget chain, no command
execution.

`patch_real.diff` is the CVE-2021-43798 fix (commit
`c798c0e958d15d9cc7f27c72113d572fa58545ce`, `pkg/api/plugins.go
getPluginAssets`): the wildcard is cleaned against `/` and rejoined to the
plugin dir's ABSOLUTE path, clamping escapes. It did NOT touch
`GetPluginMarkdown`/`pluginMarkdown`. Grafana's own 8.3.2 blog (case.json
`evidence.incomplete_fix_quote`): "This is a follow-up patch release to the
recent CVE-2021-43798 release." Honest caveat recorded in repro.log: the residual
requires an authenticated user and is limited to upper/lower-case-named `.md`
files, whereas the original seed is unauthenticated and arbitrary-file.

- **V0 = 8.3.0** (`grafana/grafana-oss:8.3.0`, `:34330`) — unauthenticated
  `/public/plugins/alertlist/../../..(x15)/tmp/pcb_canary.md` reads the canary
  (repro.log: HTTP 200 CANARY-HIT; the 43813 markdown vector also works here).
- **V1 = 8.3.1** (`grafana/grafana-oss:8.3.1`, `:34331`, target) — the 43798 fix
  BLOCKS the plugin-asset seed (HTTP 404), but as admin,
  `GET /api/plugins/alertlist/markdown/..%2f..%2f...(x15)tmp%2fpcb_canary`
  escapes the plugin dir (no containment on `name`) -> HTTP 200 CANARY-HIT.
  Incomplete fix.
- **V2 = 8.3.2** (`grafana/grafana-oss:8.3.2`, `:34332`, 43813 fix) — markdown
  path clamped: HTTP 200 but returns the alertlist plugin's OWN README, never the
  canary (repro.log).

- **Original trigger**: `GET /public/plugins/alertlist/../../../...(15)../tmp/pcb_canary.md`
  sent `--path-as-is`, unauthenticated (`poc/original_poc.py` `TRAV`/`PATH`).
- **Residual trigger**: `GET /api/plugins/alertlist/markdown/..%2f..%2f...(15)..%2ftmp%2fpcb_canary`
  with basic auth `admin:admin` (`_heldout/bypass_poc.py` `ETRAV`/`PATH`;
  handler appends `.md`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-10, flag `PCBFLAG_cddea07d3bf126427873ee9565d3fb68`: v0 seed HIT /
v1 seed 404 / v1 residual HIT / v2 residual closed; passed=true).

> NOTE: `case.yaml` records `oracle_family: sibling_endpoint` while `case.json`
> `oracle.variant` says `same_sink` — the residual genuinely hits a different
> sink function (`pluginMarkdown`) that the 43798 patch missed, as
> INCOMPLETE_FIX_ANALYSIS.md stresses; the "same-sink" label refers to the shared
> flag channel.
