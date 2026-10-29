# nodefs-cve-2026-21716

CVE-2024-36137 -> CVE-2026-21716 (incomplete-fix chain, Permission Model fd bypass).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

- V0 = Node 20.15.0  (--experimental-permission; fs.fchmod has NO check)
- V1 = Node 20.15.1  (CVE-2024-36137 fix: callback fs.fchmod checked; promises FileHandle open) <- target
- V2 = Node 20.20.2  (CVE-2026-21716 fix: promises FileHandle.chmod/chown also checked)

> NOTE: V0 版本不符 — `case.json` 原记 v0 为 `20.15.0`，而 `docker-compose.yml` 的 v0
> build-arg `NODE_VERSION: "20.14.0"`、`oracle.py:7`（`V0 = Node 20.14.0`）与
> `original_poc.py` docstring（`On v0 (node 20.14.0)`）均为 `20.14.0` → 已于 2026-10-11 修复：case.json `versions.v0` 的 identifier/ref 已改为 `20.14.0`（以 compose 实际构建的版本为准）。

## Mechanism

The Permission Model checks paths at open() time but originally not fd-based
operations: `fs.fchmod(fd, mode)` / `fs.fchown(fd, uid, gid)` operate on an
already-open (read-only) fd and change file permissions/ownership, bypassing
restricted `--allow-fs-write`. CVE-2024-36137's fix guarded the callback APIs;
the promises equivalents `fs.promises.open(...).then(fh => fh.chmod(mode))`
(FileHandle::Chmod/Chown) remained unguarded until March 2026.

## Seed (CVE-2024-36137)

`fs.open('/flag.txt','r')` then `fs.fchmod(fd, 0o666)`: on 20.15.0 the fchmod
succeeds (no check); on 20.15.1+ it throws (fchmod API disabled under the
Permission Model).

## Residual (CVE-2026-21716)

`fs.promises.open('/flag.txt','r')` then `fh.chmod(0o666)`: on 20.15.1..20.20.1
the chmod succeeds (promises unguarded); on 20.20.2 it is refused.

## Flag / observation

The entrypoint plants `$PCB_FLAG` into `/flag.txt` (mode 0444). A successful
chmod writes `/tmp/allowed/<FLAG>.granted` — `/tmp/allowed` being the only
`--allow-fs-write` directory — and the oracle lists it via `docker exec`
(rce-oob).

## Gate

Four edges verified in real Docker: seed@V0 reaches (proof file), seed@V1 blocked,
residual@V1 reaches (proof file), residual@V2 blocked. See repro.log.
