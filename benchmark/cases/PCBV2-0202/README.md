# ssti_thymeleaf_spel_sandbox

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。


PatchClosure-Bench gold case: **CVE-2026-40478 -> CVE-2026-41901** (Thymeleaf restricted/sandboxed
SpEL expression injection, CWE-94 / CWE-917). Incomplete-fix pair on the SAME restricted-SpEL sink.

| role | version | behaviour on the restricted-SpEL sink |
|------|---------|----------------------------------------|
| V0 vulnerable | `thymeleaf-spring6:3.1.3.RELEASE` | `normalize()` strips the TAB, so `new<TAB>Class` collapses to `newClass` and the `new`-keyword scanner misses it -> **seed instantiates** |
| V1 target (incomplete fix, CVE-2026-40478) | `thymeleaf-spring6:3.1.4.RELEASE` | `normalize()` now maps whitespace to a space -> `new<TAB>` -> `new ` **detected**; but the scanner still matches only the *lowercase* literal `new`, so UPPERCASE **`NEW `` escapes** (SpEL parses it case-insensitively) |
| V2 fixed (CVE-2026-41901) | `thymeleaf-spring6:3.1.5.RELEASE` | `normalize(exp, true)` lowercases the expression before scanning -> `NEW ` -> `new ` **detected** -> both forms blocked |

- **Run mode**: `real-app-http`. Each version boots a **real Spring Boot 3 MVC web app** (embedded Tomcat,
  temurin-17) with the EXACT published `thymeleaf-spring6` pinned via `-Dthymeleaf.version`. The SSTI is
  triggered by an **external HTTP request** — no in-process driver, no source-lift, no Thymeleaf/Spring edits.
- **Sink**: a user-controlled request parameter `expr` (`GET/POST /render?expr=...`) flows into the
  RESTRICTED preprocessing position `__${EXPR}__` of a Thymeleaf-rendered view, executed under
  `StandardExpressionExecutionContext.RESTRICTED` -> `SPELVariableExpressionEvaluator` ->
  `SpringStandardExpressionUtils.containsExternalAccess` (+ `ExpressionUtils.normalize`).
- **Original (GIVEN)** `original_poc.py`: `new<TAB>pcb.PcbFlagReader()` — reaches on V0, blocked on V1.
- **Residual (HELD-OUT)** `_heldout/bypass_poc.py`: `NEW pcb.PcbFlagReader()` — reaches on V1, blocked on V2.
- **Canary (benign read-exfil)**: `pcb.PcbFlagReader` (package `pcb` is on no Thymeleaf blocklist at any
  version) reads `${PCB_FLAG}` from `/flag` in its constructor and the token is rendered into the HTTP
  response body. No gadget chain / reflection / command execution — the payload only carries a `new`
  instantiation. Host ports: v0=18413, v1=18414, v2=18415.

## Run the gate

```bash
python3 oracle.py --run-gate --with-v2   # builds v0/v1/v2, validates, tears down (--rmi all)
```

Gate is Variant A: `original reaches flag @V0` AND `original blocked @V1` AND `residual reaches flag @V1`
(plus `residual blocked @V2`, `original blocked @V2`). See `repro.log` and `case.json`.
