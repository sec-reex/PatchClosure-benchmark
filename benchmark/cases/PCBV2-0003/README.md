# vite-cve-2025-31125

Vite — CVE-2025-30208 -> CVE-2025-31125 (query-suffix guard regex only matched
`raw` at query-end/before `&`; case.json records root_cause `Path_Traversal`, no
CWE ID). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real npm `vite` 5.4.14/5.4.15/5.4.16 running its actual dev server
(`vite --host 0.0.0.0 --port 5173`, per-profile Dockerfile ARG `VITE_VERSION`).
The compose entrypoint writes `${PCB_FLAG}` to `/canary.txt` at the container
filesystem root, OUTSIDE the Vite project root (`/app`), so `server.fs` allow/deny
must deny it: a plain `GET /@fs/canary.txt` returns 403 on all three versions and
the flag is only readable through the query-suffix bypass — read-exfil reflected
into the body as `export default "<content>"`, no gadget chain, no command
execution.

`patch_real.diff` is the CVE-2025-30208 upstream fix
(`packages/vite/src/node/server/middlewares/transform.ts`): strip trailing
`[?&]+$` from the URL before testing `rawRE`/`urlRE` and calling
`ensureServingAccess`, so `?import&raw??` is normalized -> checked -> 403. But
those guard regexes (`/(\?|&)raw(?:&|$)/`) still only matched `raw` at query-end
or before `&`, so `?raw?import` skipped the guard while the raw loader still read
the file — the residual GHSA-4r4m-qw57-chr8 (case.json
`evidence.incomplete_fix_quote`) reports as "a residual of the CVE-2025-30208 fix".

- **V0 = 5.4.14** (`npm:vite@5.4.14`, `:53140`) — trailing-`?` trick defeats
  `rawRE` -> `?import&raw??` reads the canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = 5.4.15** (`npm:vite@5.4.15`, `:53141`, target) — the 30208 fix BLOCKS the
  trailing-separator seed (HTTP 403), but `?raw?import` does not match
  `rawRE`/`urlRE` -> serving-access check skipped, residual still reads the canary
  (HTTP 200 CANARY-HIT). Incomplete fix.
- **V2 = 5.4.16** (`npm:vite@5.4.16`, `:53142`, 31125 fix) — guard replaced with
  `/[?&]raw\b/` (+ `inlineRE`) -> `?raw?import` now 403 (repro.log).

- **Original trigger**: `GET /@fs/canary.txt?import&raw??` (trailing `??`
  separator; `poc/original_poc.py` `PATH`).
- **Residual trigger**: `GET /@fs/canary.txt?raw?import` (leading-`?import`
  variant off the guard regexes; `_heldout/bypass_poc.py` `PATH`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-11: v0 seed 200 HIT / v1 seed 403 / v1 residual 200 HIT / v2
residual 403; passed=true).
