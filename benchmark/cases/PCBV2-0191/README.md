# simple-git-cve-2026-28291

simple-git (Node.js git wrapper) — CVE-2022-25860 -> CVE-2026-28291 (the 3.16.0
fix adds the block-unsafe-operations-plugin whose clone guard `/^\s*-u\b/` rejects
the bare `-u` upload-pack short option, but git accepts combined short-option
CLUSTERS — `-vu<cmd>` parses as `-v` + `-u<cmd>` and never matches the anchored
regex, so a dangerous upload-pack command still reaches the same sink; RCE via
argument injection; case.json root_cause `RCE`, mechanism `argument-injection`).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: the harness `require()`s the REAL published `simple-git` bytes
(3.15.1 / 3.31.1 / 3.32.0 via npm aliases) on node:20-slim + real git, and drives
the REAL `git.clone()` sink against a LOCAL bare repo (`file:///srv/repo.git`,
no network). Benign canary: the injected upload-pack merely cats the planted
`${PCB_FLAG}` (`/canary/flag.txt`, outside the app dir) into `/canary/out.txt`,
which the harness reads back — no real payload.

GHSA-jcxm-m3jx-f287 (case.json `evidence.incomplete_fix_quote`): "The flaw stems
from an incomplete fix for CVE-2022-25860, as Git's flexible option parsing allows
numerous character combinations (e.g., -vu, -4u, -nu) to circumvent the
regular-expression-based blocklist in the unsafe operations plugin. Fixed in
3.32.0." `patch_real.diff` is the CVE-2022-25860 fix (commit
`0a623e53fd4b7617ca9c4d1d51bc53d105f52b2b`, 3.16.0 / #881, adding
block-unsafe-operations-plugin). The 3.32.0 fix broadens the clone guard to the
char-class regex `/^\s*(-|--|--no-)[\dlsqvnobucj]+/`.

- **V0 = 3.15.1** (`:39670`) — only the fetch filter `/^--upload-pack(=|$)/`
  exists: the bare `-u` seed passes -> git runs the injected upload-pack ->
  flag in `/canary/out.txt` (repro.log: REACHED).
- **V1 = 3.31.1** (`:39671`, target) — the 25860 guard BLOCKS the bare `-u` seed
  ("Use of clone with option -u is not permitted without enabling
  allowUnsafePack"), but the combined-cluster residual `-vucat /canary/flag.txt>...`
  misses `/^\s*-u\b/` -> git runs it -> flag. Incomplete fix.
- **V2 = 3.32.0** (`:39672`, 28291 fix) — `-vu` matches the broadened char class
  -> GitPluginError -> blocked (repro.log: `residual_blocked_on_v2`).

- **Original trigger**: `git.clone('file:///srv/repo.git', dest,
  ["-u", "cat /canary/flag.txt>/canary/out.txt #"])`
  (`poc/original_poc.py` candidate `inject`).
- **Residual trigger**: same clone with
  `["-vucat /canary/flag.txt>/canary/out.txt #"]` (combined short-option cluster;
  `_heldout/bypass_poc.py` candidate).

Run: `python3 oracle.py --wait --v2` (gate, flag
`PCBFLAG_gatecheck_4edb7e0220fa6250` per repro run: seed reaches@v0 / seed
blocked@v1 / residual reaches@v1 / residual blocked@v2; passed=true). See
`repro.log` and `case.json`.
