# siyuan-double-url-encode-assets-traversal

SiYuan (siyuan-note/siyuan kernel) — CVE-2026-41894 → CVE-2026-54066 (path traversal via
double-URL-encoded `../`, sibling-route incomplete fix, CWE-22).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP against the unmodified
official kernel binaries** (repro.log: V0 `/export/` 200+flag; V1 `/export/` 401 but `/assets/`
200+flag = RESIDUAL; V2 `/assets/` 404; `"passed": true`, `gate_passed: true`).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL unmodified SiYuan kernel per tag straight from the official `b3log/siyuan` images (no source
copied or lifted; the case dir is scripts only). Each profile's compose entrypoint wrapper plants
the benign canary then `exec`s the image's own `/opt/siyuan/entrypoint.sh`; the kernel HTTP server
listens on container port 6806. Auth: `SIYUAN_ACCESS_AUTH_CODE_BYPASS=true` — the kernel's own
`model.CheckAuth` grants RoleAdministrator with no access-auth-code set (documented headless mode,
github issue 9709); no app code modified. Same decode flaw on all versions until each route is
patched; GHSA-p4m3-mgmm-c664 is titled "Incomplete fix of CVE-2026-41894": the patch sanitized
`/export/` but "the identical root cause remains in the `/assets/*path` route".

- **V0 = b3log/siyuan:v3.6.4** (`:38620` → 6806) — BOTH `/export/*filepath` (serveExport) and
  `/assets/*path` (GetAssetAbsPath) carry the redundant `url.PathUnescape` double-decode, no
  containment guard on either -> original 200 + flag, residual 200 + flag.
- **V1 = b3log/siyuan:v3.6.5** (`:38621`, target) — CVE-2026-41894 fix (bb481e12) adds
  `gulu.File.IsSubPath(exportBaseDir, fullPath)` to serveExport (401 otherwise) -> the `/export/`
  seed is BLOCKED. The SIBLING `/assets/` route's `GetAssetAbsPath` `url.PathUnescape` fallback is
  BYTE-IDENTICAL to v3.6.4 -> the same `%252e%252e` vector still traverses and reads the flag
  (200). Incomplete fix: one route guarded, sibling route untouched.
- **V2 = b3log/siyuan:v3.7.0** (`:38622`, -54066 fix) — `/assets/` `url.PathUnescape` fallback
  removed (serveAssets retry block dropped) + `util.IsSensitivePath` -> residual 404. (v3.7.0's
  kernel is a cobra CLI, so compose boots it with the `serve` subcommand.)

Benign canary channel: `${PCB_FLAG}` is written to `<workspace>/pcb_flag.txt`
(`/siyuan/workspace/pcb_flag.txt`) at boot — INSIDE the workspace but OUTSIDE the assets dir
(`<workspace>/data/assets`, where a normal `logo.png` asset is also planted); reachable only by
`../` traversal, not caught by `util.IsSensitivePath` (`/siyuan` is not a denylisted prefix). The
flag token is read from the REAL kernel's HTTP response body. Pure read-exfil; no write, no RCE.

- **Original trigger**: external `GET /export/%252e%252e/%252e%252e/pcb_flag.txt` (curl
  --path-as-is) — net/http percent-decodes once (`%252e`→`%2e`), serveExport's `url.PathUnescape`
  decodes a second time (`%2e`→`.`), `filepath.Join(exportBaseDir, decodedPath)` escapes
  `<workspace>/temp/export` via two `..`.
- **Residual trigger**: external `GET /assets/%252e%252e/%252e%252e/pcb_flag.txt` — same
  double-encode on the sibling route: the first `getAssetAbsPath("assets/%2e%2e/...")` misses, the
  fallback `url.PathUnescape` yields `assets/../../pcb_flag.txt` → `<workspace>/pcb_flag.txt`
  (still under `WorkspaceDir`, so `getAssetAbsPath`'s own `IsSubPath(WorkspaceDir)` guard allows
  it) and `http.ServeFile` serves the flag file.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.
