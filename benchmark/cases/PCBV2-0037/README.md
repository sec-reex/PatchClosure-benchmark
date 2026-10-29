# vm2-cve-2026-24120

CVE-2023-37466 -> CVE-2026-24120 (incomplete-fix chain, sandbox escape).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

- V0 = vm2 3.9.19  (no Promise species reset)
- V1 = vm2 3.10.0  (CVE-2023-37466 fix: resetPromiseSpecies; bypassable) <- target
- V2 = vm2 3.10.5  (CVE-2026-24120 fix)

## Mechanism

vm2 sanitizes host exceptions flowing into async callbacks. ES2022's
SpeciesConstructor lets the sandboxed code replace the promise `@@species` with a
host-side FakePromise whose executor receives the host Error object, reaching
`process.mainModule.require('child_process')` (RCE). CVE-2023-37466's fix calls
`resetPromiseSpecies()` to restore the species — but that function relies on
`[].includes` and `Object.defineProperty`, both of which the sandboxed code can
override.

## Seed (CVE-2023-37466)

The original Promise `@@species` escape payload: works on 3.9.19; on 3.10.0 the
species reset blocks it.

## Residual (CVE-2026-24120)

The same payload plus `Object.defineProperty = () => {}` before triggering the
escape: defeats the species reset on 3.10.0..3.10.4; fixed in 3.10.5.

## Flag / observation

The entrypoint plants `$PCB_FLAG` into `/flag.txt`. On escape the payload runs
`cat /flag.txt > /tmp/pcb_result.txt`; the oracle reads it via `docker exec`
(rce-oob).

## Gate

Four edges verified in real Docker: seed@V0 escapes, seed@V1 blocked,
residual@V1 escapes, residual@V2 blocked. See repro.log.
