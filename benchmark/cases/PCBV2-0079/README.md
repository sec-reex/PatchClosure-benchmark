# apache-struts-cve-2021-31805

Apache Struts 2 — **CVE-2020-17530 (S2-061) -> CVE-2021-31805 (S2-062)**, forced double OGNL
evaluation of tag attributes (CWE-917 Expression-Language Injection). Genuine incomplete fix:
S2-062 explicitly states "The fix issued for CVE-2020-17530 was incomplete."

- **V0** = struts2-core 2.5.25 (pre-S2-061; the `id` attribute is double-evaluated).
- **V1** = struts2-core 2.5.26 (**CVE-2020-17530/S2-061 patched — the target**; `id` no longer
  double-evaluates, but `name`/nameValue still re-evaluates).
- **V2** = struts2-core 2.5.30 (**CVE-2021-31805/S2-062 patched**; adds an isAcceptableExpression /
  NotExcludedAcceptedPatternsChecker guard before the second evaluation).

**REAL Struts 2 WAR on Tomcat, triggered by an EXTERNAL HTTP request** (`run_mode=real-app-http`).
Faithful-core, recipe-only: Maven pulls the EXACT published `org.apache.struts:struts2-core` at each
version and assembles a minimal WAR (`webapp/`: `EvalAction` + `eval.jsp` `<s:textfield>` + `struts.xml`
+ `web.xml`) deployed as `ROOT.war` on **Tomcat 9 / JDK8**. An external `GET /eval.action?prop=<payload>`
binds `prop` (raw String) and plants `${PCB_FLAG}` as the OGNL context var `#pcbflag`; `eval.jsp`
renders a real `<s:textfield>` whose `id`/`name` attribute is developer-forced-OGNL (`%{prop}`). The
version's own unmodified `UIBean`/`Component` code alone decides whether it double-evaluates. No
struts code is modified. Benign read-exfil canary: the attacker OGNL only reads `#pcbflag`
(= `${PCB_FLAG}`) — no command execution.

- original (id) `prop=%{#pcbflag}`: reaches on V0, **blocked on V1** (setId single-eval).
- residual (name) `prop=#pcbflag`: **reaches on V1** (name re-eval), blocked on V2 (accepted-pattern guard).

NOTE: `Driver.java`, `pom.xml`, `struts.xml` in the case root are STALE files from the old
in-process build (kept per a no-delete directive); they are NOT referenced by the current
`Dockerfile`/`docker-compose.yml`/`case.json`. The live app lives under `webapp/`.

Gate (Variant A, same UIBean OGNL forced-eval sink): `python3 oracle.py --run-gate --with-v2`
→ reach@v0=true, blocked@v1=true, bypass_reach@v1=true (passed), residual_blocked@v2=true.
Status: **gate_passed**. See `repro.log`, `patch.diff`, `case.json`.

Teardown: `PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`.

分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
