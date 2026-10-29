# froxlor-cve-2026-41231

CVE-2023-6069 -> CVE-2026-41231 (incomplete-fix chain, customer-homedir symlink escape).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

- V0 = Froxlor 2.0.11 (pre 2.1.0: `FileDir::makeCorrectDir` has NO symlink check at all)
- V1 = Froxlor 2.3.5 (CVE-2023-6069 fix 9e8f32f1 active in FTP/DirOptions/DirProtections/
      SubDomains/Apache; `DataDump.add` still resolves its export path unchecked) <- target
- V2 = Froxlor 2.3.6 (CVE-2026-41231 fix: `DataDump.add` passes `$customer['documentroot']`
      as `$fixed_homedir` to `makeCorrectDir`)

## Mechanism

CVE-2023-6069 (CWE-59, "Improper Link Resolution Before File Access", fixed 2.1.0 by
commit 9e8f32f1) added an optional `$fixed_homedir` parameter to
`FileDir::makeCorrectDir`: when given, every path component is checked with `is_link`
and any symlink resolving outside the customer homedir throws
"Found symlink pointing outside of customer home directory". The fix was applied to
`customer_ftp.php`, `Ftps`, `DirOptions`, `DirProtections`, `SubDomains` and the Apache
config cron. `DataDump.add` was missed: its export destination is built via
`FileDir::makeCorrectDir($customer['documentroot'] . '/' . $path)` with no symlink check
until 2.3.6.

## Seed (CVE-2023-6069)

`SubDomains.add(path="pcbseed/newout")` where `$HOMEDIR/pcbseed` is a symlink to the
panel web root `/var/www/html/seedout`:
- v0 (2.0.11): path passes the unchecked `makeCorrectDir`; the Apache config cron
  (`mkDirWithCorrectOwnership`, placeindex) creates `/seedout/newout/` + index.html ->
  `GET /seedout/newout/` returns 200
- v1 (2.3.5): `makeCorrectDir(..., $fixed_homedir)` throws on the symlink -> the
  subdomain is never stored -> 404

## Residual (CVE-2026-41231)

`DataDump.add(path="dumps", dump_web=1)` where `$HOMEDIR/dumps` is a symlink to
`/var/www/html/dumpout`:
- v1 (2.3.5): the export job is queued with the unresolved (symlinked) destination; the
  ExportCron writes `pcbcust-export_<ts>.tar.gz` (tar of the customer docroot, incl. the
  canary `flag.txt`) into the web root -> downloadable over HTTP; extracting `flag.txt`
  yields the flag
- v2 (2.3.6): `makeCorrectDir(..., $customer['documentroot'])` throws -> no file

## Flag

The entrypoint plants `$PCB_FLAG` into `/var/customers/webs/pcbcust/flag.txt` (canary in
the environment, not app code). The residual's exported tar.gz is downloaded over HTTP
and `flag.txt` extracted in memory; the flag appears in the observation only when the
export landed in the web root.

## Gate

Sibling-sink strict gate, four edges verified in real Docker: seed@V0 reaches (200),
seed@V1 blocked (404), residual@V1 reaches (flag in extracted export), residual@V2
blocked (API exception, no file). See repro.log.
