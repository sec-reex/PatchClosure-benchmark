# struts-fileupload-interceptor-path-traversal-rce

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。


Gold PatchClosure-Bench case: **CVE-2023-50164 (S2-066)** → **CVE-2024-53677 (S2-067)**, an
incomplete-fix pair in Apache Struts 2's legacy `FileUploadInterceptor` file-upload path traversal
(CWE-434 / CWE-22 → RCE).

- **V0** = struts `6.3.0` (pre-S2-066)
- **V1** = struts `6.3.0.2` (S2-066/CVE-2023-50164 fixed; **TARGET**, incomplete)
- **V2** = struts `6.4.0` (S2-067/CVE-2024-53677 remediation = `ActionFileUploadInterceptor`)

A minimal Struts WAR (real, unmodified `struts2-core` per profile from Maven Central) runs on
Tomcat 9. A file-upload action saves the upload to `getRealPath("/uploads") + uploadFileName`.
The attack POSTs a multipart upload whose crafted filename param traverses a **benign** JSP
(`PCB[<%= System.getenv("PCB_FLAG") %>]PCB`) into the exploded webapp root; a GET executes it and
echoes `${PCB_FLAG}`. Flag in the GET body = traversal-upload + execution succeeded.

Key differential (natural-order `ParametersInterceptor`, `getCanonicalName` strips path from the
multipart filename, so traversal must ride a text param that binds `setUploadFileName` via OGNL):
- **Original (S2-066)**: bare `uploadFileName` text param — case-equal to the interceptor's key, so
  V1's new case-insensitive `appendAll` dedup **wipes** it → blocked on V1.
- **Residual (S2-067)**: dotted `top.UploadFileName` — not case-equal to any interceptor key, so it
  **survives** the dedup and still traverses on V1. V2's migrated interceptor makes the filename
  framework-controlled → blocked.

## Reproduce

```bash
PCB_FLAG=$(python3 -c 'import secrets;print("PCBFLAG_"+secrets.token_hex(16))') \
  python3 oracle.py --run-gate --with-v2
```

Builds v0/v1/v2, runs the flag differential, prints the gate verdict, tears everything down
(`down -v --rmi all`). Gate passed on real Docker 2026-07-14 (see `repro.log`).

Files: `Dockerfile` + `webapp/` (recipe, no vendored jars/WAR), `docker-compose.yml`,
`original_poc.py` [GIVEN], `_heldout/bypass_poc.py` [HELD-OUT], `oracle.py`, `patch.diff`,
`case.json`, `repro.log`.
