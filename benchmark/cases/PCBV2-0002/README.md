# apache-http-server-cve-2021-42013

Apache HTTP Server — CVE-2021-41773 -> CVE-2021-42013 (double-encoded dot-segment
slips past the new normalizer check; case.json records root_cause
`Path_Traversal`, no CWE ID). **Genuine incomplete fix; gate passed on real Docker
over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official `httpd` images (recipe-based compose, no committed images/source).
The compose entrypoint writes `${PCB_FLAG}` to `/canary.txt` at the container
filesystem root — OUTSIDE the DocumentRoot, defended by the `Alias /pub/` mapping
(`conf/vuln.conf`; the alias directory has no default `Require all denied`, the
advisory's stated precondition). A plain `GET /canary.txt` returns 404 on all
three versions, so the flag is only readable through the traversal — read-exfil
of a protected resource reflected into the response body, no gadget chain, no
command execution.

`patch_real.diff` is the CVE-2021-41773 upstream fix (commit
`98246aa96079dad5f7b20521bbc0142a04f1c5e7`, `server/util.c ap_normalize_path`):
the `/xx/../` collapse now also accepts a second dot spelled as a literal
`%2e`/`%2E`. But that check runs AFTER the single decode-unreserved pass, so a
fully double-encoded `%%32%65` (`%2e` -> `.`) is only decoded one pass later and
slips past the new segment test — exactly what CVE-2021-42013 reports.
case.json `evidence.incomplete_fix_quote`: "It was found that the fix for
CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient."

- **V0 = 2.4.49** (`httpd:2.4.49`, `:38249`) — pre-41773 normalizer only folds a
  literal `..`, so single-encoded `.%2e`/`%2e%2e` segments walk out of the alias
  -> seed hits the canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = 2.4.50** (`httpd:2.4.50`, `:38250`, target) — the 41773 fix BLOCKS the
  single-`%2e` seed (HTTP 400), but `%%32%65` decodes too late -> the CVE-2021-42013
  residual still reads the canary (HTTP 200 CANARY-HIT). Incomplete fix.
- **V2 = 2.4.51** (`httpd:2.4.51`, `:38251`, 42013 fix) — residual closed
  (case.json `oracle.checks.residual_v2_blocked: true`; provenance: HTTP 400).

- **Original trigger**: `GET /pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt`
  (single-encoded dot-dot; `poc/original_poc.py` `PATH`).
- **Residual trigger**: `GET /pub/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/canary.txt`
  (double-encoded `..`; `_heldout/bypass_poc.py` `SEG = "%%32%65%%32%65"`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-10: v0 seed 200 HIT / v1 seed 400 / v1 residual 200 HIT / v2
residual blocked; passed=true).
