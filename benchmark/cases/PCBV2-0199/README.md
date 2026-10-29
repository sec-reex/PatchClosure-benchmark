# ssti_angular_expressions_constructor

angular-expressions (npm) — CVE-2020-5219 -> CVE-2021-21277 (expression sandbox escape / code injection;
no CWE recorded in case.json, root_cause = "Expression_Sandbox_Escape_Code_Injection").
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Node HTTP service (`harness.js`, `require('angular-expressions')` at pinned npm versions) exposes
`POST / {"expr": ...}`. It compiles the UNTRUSTED expression with the REAL, unmodified published
`expressions.compile(String(expr))` and evaluates it against an EMPTY scope `fn({})`. Same sink, same
`lib/parse.js` ASTCompiler guard mechanism (`hasOwnProperty_`); the GHSA-j6px-jwvv-vpwq advisory says the
1.0.1 sandbox "could be bypassed by using a more complex payload, using a `.constructor.constructor`
technique."

- **V0 = angular-expressions 1.0.0** (`:39720`) — NO sandbox at all (1.0.0 dropped the AngularJS expression
  sandbox): dotted `.constructor.constructor` reaches `Function` -> the env canary is read.
- **V1 = angular-expressions 1.0.1** (`:39721`, target) — CVE-2020-5219 fix added `hasOwnProperty_`
  (`Object.prototype.hasOwnProperty.call(...)`) on DOTTED member READs -> the dotted seed is BLOCKED
  (empty scope has no own `constructor`), but `computedMember` still emits raw `left[right]` and the
  CallExpression callee fetch `self.member(left.context, left.name, left.computed)` stays unguarded ->
  the computed/concat residual still escapes to `Function`. Incomplete fix.
- **V2 = angular-expressions 1.1.2** (`:39722`, CVE-2021-21277 fix) — `computedMember` rewritten to
  `(left.hasOwnProperty(right) ? left[right] : null)` and the call-callee short-circuits to null for
  non-own props -> residual BLOCKED.

Canary channel: the per-run `${PCB_FLAG}` lives ONLY in the container environment (`process.env.PCB_FLAG`)
— it is NOT on the scope and NOT in app code — so it surfaces in the evaluated `output` iff the expression
escaped the compile() sandbox to the `Function` constructor and ran `return process.env.PCB_FLAG`. Benign
framing: the "RCE" merely reads a planted env token; no real command, no persistence.

- **Original trigger**: `constructor.constructor("return process.env.PCB_FLAG")()` (dotted prototype-chain
  access; blocked on 1.0.1 by the hasOwnProperty guard).
- **Residual trigger**: `''['c'+'onstructor']['c'+'onstructor']('return process.env.PCB_FLAG')()` —
  COMPUTED member access with string concatenation dodges the dotted guard and routes the `Function`
  constructor through the unguarded call-callee fetch; verbatim the angular-expressions 1.1.2
  "should not leak" security regression test with `process` swapped for the env canary read.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
