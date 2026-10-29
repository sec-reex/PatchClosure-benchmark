# grav-cms-cleandangeroustwig-regex-bypass-cve-2025-66294

Grav CMS — CVE-2024-28116 -> CVE-2025-66294 (SSTI / Twig sandbox-escape via weak regex
blocklist, CWE-94 / CWE-1336).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Grav CMS built from the official `getgrav/grav` git tags on `php:8.3-apache`. A thin
`pcb-probe` Grav plugin (`user/plugins/pcb-probe/pcb-probe.php`) exposes `POST /pcb-probe`
(JSON `{"payload": "<twig>"}`) that feeds the submitted Twig source through Grav's own REAL
`Twig::processString()` — which calls the per-version `Security::cleanDangerousTwig()`. Nothing
is source-lifted. Same sink for both CVEs: the `cleanDangerousTwig()` regex in front of
`processString()`. The advisory calls CVE-2025-66294 a weak-regex failure to sanitize *nested*
Twig calls via `evaluate_twig`.

- **V0 = grav 1.7.44** (`:39744`) — `Security.php` has NO `cleanDangerousTwig` method
  (grep count 0); `processString()` renders untrusted Twig with no sanitiser -> the direct
  registration reaches the canary.
- **V1 = grav 1.7.45** (`:39745`, target) — CVE-2024-28116 fix INTRODUCES
  `Security::cleanDangerousTwig()`: a single-pass 8-word regex blocklist
  (`registerUndefinedFunctionCallback`, `twig.getFunction`, `call_user_func`, ...) called from
  `Twig::processString()` (line 397) -> the direct form is commented out, BLOCKED. But
  `evaluate_twig` is NOT on the blocklist, and `GravExtension::evaluateTwigFunc()` renders the
  inner string in a FRESH `Twig\Environment` without ever calling `cleanDangerousTwig` -> the
  CVE-2025-66294 residual still reaches the canary. Incomplete fix.
- **V2 = grav 1.8.0-beta.27** (`:39746`, -66294 fix) — `cleanDangerousTwig()` rewritten to a
  4-pass filter; `evaluate_twig`/`evaluate` added to the blocklist; delimiter-independent
  Pass 3 (`/\b(evaluate_twig)\s*\(/i`) strips the outer call -> residual BLOCKED.

Benign canary channel: the payload registers the harmless PHP builtin `getenv` as the LIVE Twig
engine's undefined-function callback (`grav.twig.twig.registerUndefinedFunctionCallback('getenv')`,
where `grav.twig.twig` is the real `Twig\Environment` from the Grav singleton) and then resolves
the function named `PCB_FLAG` (`grav.twig.twig.getFunction('PCB_FLAG')`), so the engine runs
`getenv('PCB_FLAG')`; `${PCB_FLAG}` is injected into each container's env by docker-compose and
the token appears in the `POST /pcb-probe` response `output` field only if the sanitiser failed
to neutralise the callback registration. No gadget chain, no `system()`, no shell.

- **Original trigger**: direct form `{{ grav.twig.twig.registerUndefinedFunctionCallback('getenv') }}{{ grav.twig.twig.getFunction('PCB_FLAG') }}` — both blocklisted words appear literally
  inside single `{{..}}` blocks, so V1's regex comments them out; on V0 (no sanitiser) it reaches
  the canary.
- **Residual trigger**: nested form `{{ evaluate_twig('{{ grav.twig.' ~ 'twig.regist' ~
  'erUndefinedFunctionCallback("getenv") }}{{ grav.twig.twig.get' ~ 'Function("PCB_FLAG") }}') }}`
  — Twig `~` concatenation splits `registerUndefinedFunctionCallback` and `twig.getFunction` so
  neither appears contiguously in the outer string, `evaluate_twig` is off the 1.7.45 blocklist,
  and the reconstructed inner template is rendered by `evaluateTwigFunc()`'s fresh
  `Twig\Environment` with no second `cleanDangerousTwig` pass (added/blocked in 1.8.0-beta.27).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: `repro.log` (tail) claims stale source-lift artefacts `guard_v0.php`, `guard_v1.php`,
> `guard_v2.php`, `harness.php` are "left in place per policy", but none of them exists in the
> case directory (verified by `ls guard_v0.php guard_v1.php guard_v2.php harness.php`).
