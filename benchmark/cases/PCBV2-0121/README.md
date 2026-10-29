# gogs-cve-2025-64111

Gogs — CVE-2024-56731 -> CVE-2025-64111 (the 0.13.3 fix adds `osutil.IsSymlink`
checks only on the IsNewFile / move / upload / delete paths; the API router calls
`UpdateRepoFile` with `IsNewFile=false` and `OldTreeName==NewTreeName` — a pure
update — matching NONE of the guarded conditions, so a write through the file
symlink still reaches `.git/config`; symlink traversal -> RCE via
`core.fsmonitor`, CWE-59 / CWE-78). **Genuine incomplete fix; gate passed on real
Docker over EXTERNAL HTTP (Variant A same-sink).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official Gogs images (`gogs/gogs:0.13.2` / `0.13.3` / `0.13.4`). Benign
rce-oob canary: the entrypoint writes `${PCB_FLAG}` to `/data/pcb/flag.txt` and
creates `/data/pcb/fsmon.sh` (`cat /data/pcb/flag.txt > /tmp/pcb_result.txt`);
the injected `.git/config` sets `core.fsmonitor = /data/pcb/fsmon.sh`, so the
next `git add` invoked by Gogs runs the hook and captures the flag — read back
via `docker exec` from `/tmp/pcb_result.txt`. No real payload; the only executed
command reads the planted canary.

`patch_real.diff` is the CVE-2024-56731 first-fix (commit
`1cba9bc81b6febf2c2bef3784665c22ada312bbf`, 0.13.2 -> 0.13.3,
`internal/db/repo_editor.go`): `osutil.IsSymlink` checks added for the
`IsNewFile` and rename branches. GHSA-gg64-xxr9-qhjp (case.json
`evidence.incomplete_fix_quote`): "UpdateRepoFile has a security check under some
if conditions. However, the UpdateRepoFile call in the API router will NOT match
any of them. It is still possible to update the .git/config file via the API
router." The 0.13.4 fix (commit `c3eca1f`) extends the symlink check to the
update path.

- **V0 = 0.13.2** (`gogs/gogs:0.13.2`, `:23400`) — web-editor UPLOAD path
  (`POST /{owner}/{repo}/upload-file` + commit): `UploadRepoFiles` copies without
  any symlink check -> `link` -> `.git/config` overwritten -> fsmonitor fires ->
  flag (repro.log: REACHES).
- **V1 = 0.13.3** (`gogs/gogs:0.13.3`, `:23401`, target) — the 56731 fix BLOCKS
  the upload seed (IsSymlink check), but `PUT /api/v1/repos/{owner}/{repo}/contents/link`
  (pure update, no matching guard) still follows the symlink and writes
  `.git/config` -> fsmonitor -> flag. Incomplete fix. (The API may return 500
  while the write still succeeded — the fsmonitor flag is written before the
  commit fails; bypass_poc checks the result file regardless of HTTP status.)
- **V2 = 0.13.4** (`gogs/gogs:0.13.4`, `:23402`, 64111 fix) — API PUT symlink
  update blocked (HTTP 500, fsmonitor never fired, no flag;
  case.json `status.frozen_2026-08-02`).

- **Original trigger**: push `link -> .git/config`, then web upload of a file
  NAMED `link` carrying the malicious config, then commit
  (`poc/original_poc.py` `run(version="v0")`; `malicious_config()` from
  `gogs_util.py`).
- **Residual trigger**: same symlink, then
  `PUT /api/v1/repos/{owner}/{repo}/contents/link` with the base64 config
  (`_heldout/bypass_poc.py` `run(version="v1")`).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-14, flag
`PCBFLAG_dee4af024467c965ae2b91bba00ae4b7`: original REACHES@v0 / blocked@v1 /
bypass reaches@v1; passed; V2 negative re-gated 2026-08-02). See `repro.log` and
`case.json`.

> NOTE: `docker-compose.yml` pins `platform: linux/arm64` and
> `pull_policy: never` on the three official `gogs/gogs` images — on a fresh
> host `up` will not fetch them; the images must pre-exist locally.
