# mlflow-cve-2024-3848

MLflow — CVE-2023-6909 -> CVE-2024-3848 (the fix's `validate_query_string` only
checks the URL QUERY of `artifact_location`; `urlparse` had already split the
`#` into `fragment`, which is never checked, so moving the traversal from `?` to
`#` bypasses it; Path_Traversal; case.json records root_cause `Path_Traversal`,
no CWE ID). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL
HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real published MLflow from PyPI (`pip install mlflow==2.9.1` / `2.11.0` /
`2.12.1`, python:3.10-slim) running its actual server
(`mlflow server --serve-artifacts`, backend sqlite). The entrypoint writes
`${PCB_FLAG}` to `/canary.txt` at the filesystem root, OUTSIDE the artifact root
`/mlartifacts`; the flag is only observable in a model-version artifact-download
response (`GET /model-versions/get-artifact?path=canary.txt`) — read-exfil, no
gadget chain, no command execution. Both chains (seed and residual) are the same
4 steps: poison an experiment's `artifact_location`, create a run, register a
model version with `source="/"` (whose `_validate_source` resolves the poisoned
run artifact_uri as a raw filesystem path to `PosixPath('/')`), then download
`canary.txt` through the version.

case.json `evidence.incomplete_fix_quote`: "CVE-2024-3848 is a path traversal
bypass for CVE-2023-6909. The CVE-2023-6909 fix added validate_query_string to
_create_experiment (blocking '..' in the URL query string of artifact_location),
but did NOT validate the URL fragment ('#'). By moving the traversal from '?' to
'#', the attacker bypasses the query-string check." `patch_real.diff` is the
CVE-2023-6909 fix (commit `1da75dfcec…`, `mlflow/utils/uri.py`); the 2.12.1 fix
(commit `f8d51e2152`) adds the fragment check.

- **V0 = 2.9.1** (`pip:mlflow==2.9.1`, `:40290`) — no validation of
  `artifact_location`; the query-string payload
  `http://host?/../../../../../../../../../` poisons the experiment -> run ->
  version -> `/canary.txt` read (repro.log: result = flag).
- **V1 = 2.11.0** (`pip:mlflow==2.11.0`, `:40291`, target) — the 6909 fix BLOCKS
  the query seed (`create_experiment` -> 400 INVALID_PARAMETER_VALUE), but
  `http://host#/../../../../../../../../` parses to `query=""` (passes) with the
  traversal in the unchecked fragment -> same chain reads `/canary.txt`.
  Incomplete fix.
- **V2 = 2.12.1** (`pip:mlflow==2.12.1`, `:40292`, 3848 fix) — both payloads
  blocked at `create_experiment` (400; repro.log).

- **Original trigger**: `POST /api/2.0/mlflow/experiments/create` with
  `"artifact_location": "http://host?/../../../../../../../../../"` then run +
  `model-versions/create source="/"` + `GET /model-versions/get-artifact?path=canary.txt`
  (`poc/original_poc.py` candidate).
- **Residual trigger**: identical chain with
  `"artifact_location": "http://host#/../../../../../../../../"` (fragment
  traversal; `_heldout/bypass_poc.py` `artifact_location`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate: original@v0 reaches / original@v1 blocked / bypass@v1 reaches /
bypass@v2 + original@v2 blocked; GATE PASSED=True).
