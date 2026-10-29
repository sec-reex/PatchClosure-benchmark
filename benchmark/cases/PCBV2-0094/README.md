# daptin-cve-2026-44349

Daptin — CVE-2026-41422 -> CVE-2026-44349 (SQL injection via a sibling code path not covered
by the prior patch; case.json `root_cause`: SQLi — no CWE code is stated anywhere in the case
files).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (clean --run-gate,
2026-07-17).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official `daptin/daptin` Docker images under EXTERNAL HTTP. Two API endpoints both take a
user-supplied column name: `GET /aggregate/:typename?column=...` (projection compiled via
`goqu.L()`, raw SQL literal) and `GET /api/<entity>?query=[{"column":...,"operator":"fuzzy",...}]`
(`processFuzzySearch` in `server/resource/resource_findallpaginated.go` interpolates the column
into `goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col))`). The CVE-2026-41422 fix (v0.11.4,
commit `7212c3a`, GHSA-rw2c-8rfq-gwfv) rewrote `resource_aggregate.go` only (`parseAggExpr` +
schema column whitelist) and did not cover the fuzzy path — case.json quotes the advisory: "The
fix for CVE-2026-41422 modified resource_aggregate.go but did not cover this path." Canary: the
oracle seeds a `pcb_canary` entity (permission=0, so a self-registered non-admin attacker
cannot read it via the normal API) from the HOST and inserts a `${PCB_FLAG}` token row into the
Daptin SQLite DB; the injections read `pcb_canary.token` (read-exfil, flag in HTTP response).
No shell, no command execution.

- **V0 = daptin v0.9.82** (`:39082`) — aggregate `column` goes verbatim into `goqu.L()` with no
  validation -> the correlated-subquery projection returns the canary inline (fuzzy path also
  open).
- **V1 = daptin v0.11.4** (`:39114`, target; CVE-2026-41422 fix) — `parseAggExpr` validates
  aggregate columns against the schema whitelist -> the aggregate seed returns an "invalid
  column ... invalid expression" error -> seed BLOCKED. But `processFuzzySearch` still splits
  the fuzzy `column` on comma and interpolates each segment into the raw `LOWER(%s) LIKE ?`
  expression with no whitelist -> the residual stays open. Incomplete fix.
- **V2 = daptin v0.11.5** (`:39115`, CVE-2026-44349 fix) — fuzzy-search columns are validated
  via `tableInfo.GetColumnByName()` and non-schema columns are skipped ("no valid columns for
  fuzzy search") -> residual BLOCKED (row-count differential test returns `total=0`,
  `sqli_works: false`).

- **Original trigger**: `GET /aggregate/world?column=(SELECT token FROM pcb_canary ORDER BY id
  DESC LIMIT 1) as exfil` — the injected projection lands in the JSON response as
  `{"exfil": "PCBFLAG_..."}`. Reaches on v0.9.82, blocked on v0.11.4.
- **Residual trigger**: `GET /api/world?query=[{"column":"table_name) LIKE 'XYZNOEXIST' OR
  (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB '<prefix>*' OR LOWER(table_name",
  "operator":"fuzzy","value":"XYZNOEXIST"}]` — comma-free injection (the code splits on comma)
  that closes the `LOWER(...) LIKE` expression and adds a case-sensitive SQLite `GLOB` prefix
  test in an OR, giving a boolean blind channel over the result `total` (total>0 = match);
  ~40 requests extract the 40-character flag character-by-character. Reaches on v0.11.4
  (extracted `PCBFLAG_e48c665e8118dd3c577a0c967a97b301`, matching the planted flag), blocked
  on v0.11.5.

Run: `python3 oracle.py --run-gate` (full lifecycle, v0+v1+v2). See `repro.log` and `case.json`.
