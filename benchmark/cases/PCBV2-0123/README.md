# gradio-file-endpoint-is-in-or-equal-bypass

Gradio — CVE-2023-51449 -> CVE-2024-47164 (on the SAME `gradio.utils.is_in_or_equal`
containment sink reached via the `/file=` route: the 4.11.0 fix changes the check
from `str(rel).startswith("..")` to `".." in str(rel)`, but `abspath()` never
resolves symlinks, so a symlink inside the allowed dir escapes with a relative
path containing no `..`; the 5.0.0 fix adds `.resolve()`; Path_Traversal; no CWE
ID recorded in case.json). **Genuine incomplete fix; gate passed on real Docker
over EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real published PyPI gradio wheels (4.10.0 / 4.11.0 / 5.0.0, python:3.11-slim,
era-pinned web-stack deps since gradio leaves fastapi/pydantic/jinja2/uvicorn
unbounded) running the real gradio server with `allowed_paths=["/gradio_tmp"]`.
Read-exfil canary: the compose entrypoint writes `${PCB_FLAG}` to `/flag` at the
filesystem root (OUTSIDE the allowed dir), and plants `/gradio_tmp/sub` (an
"uploaded" subdir) and `/gradio_tmp/escape` -> `/` (a symlink) inside the allowed
dir; the flag appears in the `/file=` response body only when `is_in_or_equal`
is bypassed.

Sink evolution (source-verified per tag, repro.log): V0 4.10.0
`str(rel).startswith("..")`; V1 4.11.0 `".." in str(rel)` (the CVE-2023-51449
fix, commit `1b9d4234d6c25ef250d882c7b90e1f4039ed2d76`); V2 5.0.0
`abspath(p).resolve()` (the CVE-2024-47164 fix). GHSA-77xq-6g77-h274 (case.json
`evidence.incomplete_fix_quote`): "The is_in_or_equal function may be bypassed
... Ensure that all file paths are properly resolved and absolute."

- **V0 = 4.10.0** (`:47610`) — subdir escape: the relative path
  `sub/../../flag` starts with `sub`, not `..` -> check passes -> FileResponse
  serves `/flag` (repro.log: FLAG [200]).
- **V1 = 4.11.0** (`:47611`, target) — the 51449 fix BLOCKS the literal-`..` seed
  (403), but `/gradio_tmp/escape/flag` traverses the in-allowed-dir symlink:
  relative `escape/flag` has no `..` AND `abspath()` keeps the symlink unresolved
  -> FileResponse follows it -> `/flag` served (FLAG [200]). Incomplete fix.
  (A pure literal-`..` residual IS caught by V1's substring check — the genuine
  V1-surviving residual is the symlink form, documented in `_heldout/evidence.json`.)
- **V2 = 5.0.0** (`:47650`, 47164 fix) — `.resolve()` collapses the symlink ->
  `relative_to(/gradio_tmp)` ValueError -> 403; both payloads blocked while a
  legit `/gradio_tmp` file is still served (route-health control).

- **Original trigger**: `GET /file=/gradio_tmp/sub/../../flag` (subdir + `..`
  escape; `poc/original_poc.py` `PATH`).
- **Residual trigger**: `GET /file=/gradio_tmp/escape/flag` (symlink traversal;
  `_heldout/bypass_poc.py` `PATH`; on V2 the route moved under the API prefix:
  `GET /gradio_api/file=...`, same sink).

Run: `python3 oracle.py --run-gate --with-v2` (gate, flag
`PCBFLAG_a0c56cf55388927cdacbe4425fbdffcd`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / v2 original+residual blocked; passed=true, `_env_ready`
all true). See `repro.log` and `case.json`.
