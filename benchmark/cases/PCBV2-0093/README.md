# dagu-cve-2026-33344

Dagu — CVE-2026-27598 -> CVE-2026-33344 (the 27598 fix added `ValidateDAGName` +
`filepath.Base` on the CREATE path only; GET/DELETE/RENAME/EXECUTE still pass
`{fileName}` straight to `locateDAG`, whose separator branch calls `filepath.Abs`
with no containment — a `%2F`-encoded traversal READS files outside the DAGs dir;
Path_Traversal, CWE-22-class; case.json records root_cause `Path_Traversal`, no
CWE ID). **Genuine incomplete fix (sibling-sink write->read); gate passed on real
Docker over EXTERNAL HTTP.**

Incomplete-fix writeup: [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md).

Real Dagu built from pinned git refs (`6c53bfd` = parent of the 27598 fix
`e2ed589`/PR #1691; tag `v2.3.0`; `7d07fda` = PR #1803) via `go build` on
`golang:1.26-alpine`, Go API only (`DAGU_HEADLESS=true`, basic auth admin/admin).
The compose entrypoint writes `${PCB_FLAG}` to `/flag/canary.yaml` at container
root, OUTSIDE the served DAGs dir `/data/dags` (normal
`GET /api/v1/dags/canary/spec` -> 404); the flag is only observable in the JSON
`spec` field of a `GetDAGSpec` response — read-exfil, no gadget chain, no command
execution.

`patch_real.diff` is the CVE-2026-27598 fix (commit `e2ed589105d79273e4e6ac8eb31525f765bb3ce4`,
`internal/core/validator.go` + `internal/persis/filedag/store.go`):
`ValidateDAGName` rejects `.`/`..`, and `generateFilePath` switches to
`filepath.Base` with a `baseDir` containment check. Incomplete — that guards the
CREATE verb only. GHSA-ph8x-4jfv-v9v8 (case.json
`evidence.incomplete_fix_quote`): "This patched the CREATE path. The remaining API
endpoints - GET, DELETE, RENAME, EXECUTE - all pass the {fileName} URL path
parameter to locateDAG without calling ValidateDAGName." The completing fix
(commit `7d07fda`, PR #1803) adds a middleware running `ValidateDAGName` on every
strict-handler request's FileName field.

- **V0 = 6c53bfd** (`:39100`) — no CREATE guard: `POST /api/v1/dags` with a
  traversal name writes outside `/data/dags` (HTTP 201); the `%2F` read also
  returns the canary (200 + FLAG).
- **V1 = v2.3.0** (`ghcr.io/dagucloud/dagu:2.3.0`, `:39101`, target) — the 27598
  fix BLOCKS the create-write seed (HTTP 400 bad_request), but
  `GET /api/v1/dags/..%2F..%2F...%2Fflag%2Fcanary/spec` -> chi captures the
  `%2F`s as one segment, oapi-codegen `PathUnescape`s them to `/`,
  `locateDAG`'s separator branch hits `filepath.Abs` with no containment ->
  HTTP 200 + flag in `spec`. Incomplete fix.
- **V2 = 7d07fda** (`:39102`, PR #1803) — FileName middleware -> HTTP 400, no
  flag (repro.log matrix).

- **Original trigger (seed, WRITE channel)**: `POST /api/v1/dags` with
  `{"name": "../../../../../../flag/pwned"}` (`poc/original_poc.py` `NAME`;
  honest note in-file: a WRITE cannot emit the read-exfil canary).
- **Residual trigger (READ channel)**:
  `GET /api/v1/dags/..%2F..%2F..%2F..%2F..%2F..%2Fflag%2Fcanary/spec`
  (`_heldout/bypass_poc.py` `ENC`; 6 encoded `../` segments, `.yaml` appended by
  `findDAGFile`).

Run: `python3 oracle.py --run-gate` (Variant B sibling gate, flag
`PCBFLAG_8c5286f0608e10de09b9f5a96e19cef8`: residual_reaches_flag_on_v1=true /
residual_blocked_on_v2=true / seed_closed_on_v1=true (write 201@v0 -> 400@v1);
passed=true). See `repro.log` and `case.json`.

> NOTE (1): case.json `versions.v2` pins commit `7d07fda8f9de3ae73dfb081ccd0639f8059c56bb`
> and explicitly says "NOT tag v2.3.1 -- v2.3.1 tree still vulnerable", but
> `docker-compose.yml` builds V2 from the official image
> `ghcr.io/dagucloud/dagu:2.3.1` (its own comment claims "33344 closed in later
> trees"). The two disagree on what V2 actually runs.
> NOTE (2): case.json `oracle.variant` is `sibling_sink` (write seed cannot reach
> the read-exfil flag; prior 2026-07-10 run false-failed by forcing Variant A),
> yet `oracle.checks` still carries the Variant-A key names
> (`seed_v0_reaches` etc.) — the repro.log sibling gate uses
> `seed_closed_on_v1` / `residual_*` instead.
