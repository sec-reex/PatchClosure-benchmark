# pyload-cve-2026-35592

pyLoad — CVE-2026-32808 -> CVE-2026-35592 (the 32808 fix (commit `5f4f0fa`)
added `fs.is_within_directory()` via `os.path.commonpath()` and wired it into
SevenZip/UnRar/UnZip/HjSplit and `UnTar.list()/verify()`, but LEFT
`UnTar._safe_extractall()` on the STRING-level `os.path.commonprefix()` check,
which passes for a SIBLING directory sharing a string prefix — a tar member
`../pkg_evil/CANARY.txt` escapes the extraction dir; Path_Traversal / zip-slip
write; case.json records root_cause `Path_Traversal`, no CWE ID). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP (Variant B
sibling-sink).**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real pyLoad per profile (whole repo at pinned commits installed `pip install
".[plugins]"` from the GitHub archive tarball; python:3.11-slim — tarfile has no
default data filter on 3.11, so the plugin-level `UnTar` check decides zip-slip);
`pyload` runs on :8000 with a preseeded userdir. SIBLING-SINK pair (Variant B —
different plugins/verbs/archives, cannot share one flag channel): seed
CVE-2026-32808 = `SevenZip.verify()` join-then-`os.remove` (arbitrary DELETE via a
7z entry name); residual CVE-2026-35592 = `UnTar._safe_extractall` ->
`tarfile.extractall` (arbitrary WRITE via tar zip-slip). State-write canary: the
escaping tar member `../pkg_evil/CANARY.txt` CARRIES the per-run `${PCB_FLAG}` as
its content; the flag is observable in the harness result (`oob_content`) only if
the out-of-bounds write succeeded.

GHSA-mvwx-582f-56r7 (case.json `evidence.incomplete_fix_quote`): "The correct
function os.path.commonpath() was added to the codebase in the GHSA-7g4m-8hx2-4qh3
fix (commit 5f4f0fa) but was never applied to _safe_extractall(), making this an
incomplete fix." `patch_real.diff` is the CVE-2026-32808 first-fix (commit
`5f4f0fa5fed3520e57f2cb5a1053e3654c082eea`, `src/pyload/core/utils/fs.py`:
`is_within_directory` + traversal-safe `safejoin`). The CVE-2026-35592 fix
(commit `0fc250c9`) switches `_safe_extractall` to `commonpath`.

- **V0 = `e81028fe` (pre-32808-fix)** (`:39590`) — seed: the 7z entry deletes the
  planted out-of-bounds canary via plain `os.path.join` (`canary_survived=false`);
  the tar residual also escapes.
- **V1 = `5f4f0fa5` (32808-fixed)** (`:39591`, target) — the 32808 fix CLOSES the
  delete seed (`fs.safejoin` raises "ValueError: Path traversal attempt detected";
  canary survives), but the residual tar member `../pkg_evil/CANARY.txt` passes
  `commonprefix(["/data/dl/pkg", "/data/dl/pkg_evil/CANARY.txt"]) ==
  "/data/dl/pkg"` -> written OUT-OF-BOUNDS carrying the flag. Incomplete fix.
- **V2 = `0fc250c9` (35592-fixed)** (`:39592`) — `commonpath` ->
  "ArchiveError: Attempted Path Traversal in Tar File (CVE-2007-4559)",
  `oob_content=""` (repro.log).

- **Original trigger (seed, DELETE channel)**: 7z entry name `../seed_evil/DELME.txt`
  driven through `SevenZip.verify()`'s join-then-remove with each version's REAL
  join primitive (`poc/original_poc.py` candidate; the V0/V1 delta is
  `os.path.join` vs real `fs.safejoin`).
- **Residual trigger (WRITE channel)**: tar with the single member
  `../pkg_evil/CANARY.txt` whose content is `ZIPSLIP-WRITE <flag>`
  (`_heldout/bypass_poc.py` `build_tar`/`candidate`).

Run: `python3 oracle.py --run-gate` (gate 2026-07-10, flag
`PCBFLAG_38d0e260fb166f8340ecd7a8f57bcd4f`: seed_closed_on_v1=true /
residual_reaches_flag_on_v1=true / residual_blocked_on_v2=true; passed=true).
See `repro.log` and `case.json`.

> NOTE: case.json `provenance`/`audit` describe the image as ASSEMBLING partial
> source ("UnTar.py verbatim; fs/purge ast-sliced verbatim; inert extractor base
> class stubbed" via `assemble.py`), while the `Dockerfile` header claims a
> whole-tree install ("Not raw file slices, not assemble.py, not a function
> harness"). The two descriptions disagree on how much pyLoad source the build
> actually runs; no build was executed during this README pass to resolve it.
> Remediation 2026-10-11: the legacy generation's HTTP gate — `harness/server.py`
> + `oracle.py` (endpoints `/health` `/residual` `/seed`, env `SEED_USES_SAFEJOIN`,
> and the `python3 oracle.py --run-gate` run recorded above) — is not wired into
> the active compose (the Dockerfile installs the whole tree and `entrypoint.sh`
> execs real `pyload` on :8000), so both files were removed and archived under
> `benchmark/replacements_2026-10-11/PCBV2-0179/` (see case.json `stale_files`
> and `provenance.notes`); the active verification path is `scripts/verify.sh` +
> `poc/seed_exec.py` via `docker exec`.
