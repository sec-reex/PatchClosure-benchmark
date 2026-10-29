# ssti_n8n_expression_sandbox

n8n / n8n-workflow (npm) — CVE-2025-68613 -> CVE-2026-25049 (expression sandbox escape -> code
injection, CWE-913 per GHSA-6cqr-8cfr-67f8).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Node HTTP service (`harness.js`) imports the REAL pinned n8n-workflow npm package VERBATIM per
profile (`expression-evaluator-proxy.js` `evaluateExpression` — the exact `@n8n/tournament` instance
wired with `before:[FunctionThisSanitizer]`, `after:[PrototypeSanitizer, DollarSignValidator]` — plus
`expression-sandboxing.js` and `Expression.initializeGlobalContext(data)` for the real shadowed
context) and exposes `POST / {"expr": ...}`. No n8n source is modified. Same sink, same
`expression-sandboxing.ts` AST-hook mechanism; GHSA-6cqr-8cfr-67f8 (CVE-2026-25049) says
"Additional exploits in the expression evaluation of n8n have been identified and patched following
CVE-2025-68613."

- **V0 = n8n-workflow 1.116.0** (n8n 1.119.1, `:39730`) — NO `FunctionThisSanitizer`: in non-strict JS a
  regular-function IIFE has `this` === the Node global -> `this.process` is the REAL process -> the seed
  reads the env canary.
- **V1 = n8n-workflow 1.119.0** (n8n 1.122.0, `:39731`, target) — CVE-2025-68613 fix added
  `FunctionThisSanitizer` as a Tournament before-hook (IIFEs become `.call({process:{}}, ...)`, callbacks
  become `.bind({process:{}})`) -> the this-binding seed is BLOCKED (`this.process.env` is undefined) —
  but `PrototypeSanitizer` is still `visitMemberExpression` ONLY, with NO `visitObjectPattern`, so object
  DESTRUCTURING extracts `constructor` without any MemberExpression node and still reaches the REAL
  `Function` constructor. Incomplete fix.
- **V2 = n8n-workflow 1.120.7** (n8n 1.123.17, `:39732`, CVE-2026-25049 fix) — `PrototypeSanitizer` gains
  `visitObjectPattern` (computed/TemplateLiteral destructuring keys -> `ExpressionComputedDestructuringError`;
  unsafe string/identifier keys -> `ExpressionDestructuringError`) and `FunctionThisSanitizer` is renamed
  `ThisSanitizer` with `this`/`globalThis` neutralised -> residual BLOCKED.

Canary channel: the per-run `${PCB_FLAG}` lives ONLY in the container environment (`process.env.PCB_FLAG`)
and is mirrored by the entrypoint at `/canary/flag.txt` — NOT on the sandbox `data` context and NOT in app
code. It surfaces in the evaluated `output` iff the expression escaped the sandbox to the real `process`
or the real `Function` constructor. Benign framing: the escaped command only `cat`s the planted canary
file — no real payload, no persistence.

- **Original trigger**: `{{ (function(){ return this.process.env.PCB_FLAG })() }}` — regular-function IIFE,
  `this` binds to the Node global on 1.116.0; blocked on 1.119.0 by `FunctionThisSanitizer`.
- **Residual trigger**: `{{ (()=>{const {[`constructor`]: a} = Array; const {[`constructor`]: F} = a; return
  F("return process.mainModule.require('child_process').execSync('cat /canary/flag.txt').toString()")()})() }}`
  — TemplateLiteral computed-key destructuring (the `visitObjectPattern` uncovered branch) fetches
  `Function` and `new Function(body)` runs in the global scope with the REAL `process`; blocked on 1.120.7
  by `PrototypeSanitizer.visitObjectPattern` (`ExpressionComputedDestructuringError`).

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
