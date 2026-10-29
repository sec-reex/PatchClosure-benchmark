# october-cms-cve-2020-26231

October CMS — CVE-2020-15247 -> CVE-2020-26231 (Twig sandbox-escape method blocklist, CWE-74
code injection / sandbox escape).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL October CMS (git tags `v1.0.468/469/470`, composer-installed at build time) behind Apache/PHP
with MySQL 8.0. The entrypoint (`entrypoint.sh`) plants the canary at `/var/canary.txt` (OUTSIDE the
webroot) from `${PCB_FLAG}` and pre-creates two CMS pages in the demo theme: `/canary-original` and
`/canary-bypass`. Both pages are Twig sandbox escapes that register the benign PHP callable
`file_get_contents` on `this.page` and read the canary into the HTTP response body — no shell, no
real RCE payload. Same sink in all three versions = the Twig `SandboxExtension` /
`SecurityPolicy::checkMethodAllowed()` method blocklist guarding PHP method calls from templates.

- **V0 = October CMS Build 468** (`:39468`) — no `SecurityPolicy` at all -> `addDynamicMethod` (and
  `bindEvent`) both work -> canary read -> flag.
- **V1 = October CMS Build 469** (`:39469`, target) — CVE-2020-15247 fix (commit `4c650bb`,
  `patch_real.diff`) introduces `System\Twig\SecurityPolicy` blocking `addDynamicMethod` +
  `addDynamicProperty` only -> the -15247 seed dies with `SecurityNotAllowedMethodError`, but
  `bindEvent` / `bindEventOnce` (from the `Emitter` trait on the same Page object) are NOT in the
  blocklist -> the CVE-2020-26231 residual still reads the canary. Incomplete fix.
- **V2 = October CMS Build 470** (`:39470`, -26231 fix) — `SecurityPolicy` extended to also block
  `bindEvent` + `bindEventOnce` -> residual BLOCKED.

Benign shadow-class channel: the canary is a passive file read via PHP `file_get_contents`;
success = flag token substring in the HTTP 200 body of the CMS page.

- **Original trigger**: `GET /canary-original` —
  `{{ this.page.addDynamicMethod('readCanary', 'file_get_contents') }}{{ this.page.readCanary('/var/canary.txt') }}`;
  blocked on V1/V2 (`SecurityNotAllowedMethodError: addDynamicMethod`).
- **Residual trigger**: `GET /canary-bypass` —
  `{% set _bind = this.page.bindEvent('pcb.read', 'file_get_contents') %}{{ this.page.fireEvent('pcb.read', ['/var/canary.txt'])|join }}`;
  registers `file_get_contents` as an event listener and fires it — passes the V1 blocklist
  (method name `bindEvent` not listed), blocked on V2.

Run: `python3 oracle.py --run-gate` (or `--gate` with envs already up). See `repro.log` (gate run
2026-07-17, flag `PCBFLAG_gate_...`: seed 200+flag on V0 / exception on V1; bypass 200+flag on V1 /
exception on V2) and `case.json`.

Note: `patch_real.diff` is the ORIGINAL CVE-2020-15247 fix (468->469, adds the sandbox +
`SecurityPolicy` with only `addDynamicMethod`/`addDynamicProperty` in `$blockedMethods`);
`patch.diff` is the residual fix (469->470, adds `bindEvent`/`bindEventOnce`) — per the case
convention `patch.diff` is what the method is given, `patch_real.diff` the held-out real lineage.
