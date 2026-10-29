# grafana-loki-cve-2026-21726

Grafana Loki — CVE-2021-36156 -> CVE-2026-21726 (the 2.3.0 fix restricted the
TENANT-ID (`X-Scope-OrgID`) input to the Ruler rule-store sink
`filepath.Join(<store dir>, <tenant id>, <namespace>)` but left the SIBLING
namespace URL segment unguarded — `parseNamespace` applies exactly one
`url.PathUnescape` with no traversal check — so a DOUBLE-URL-encoded
`../` namespace traversal reads arbitrary files; Path_Traversal; no CWE ID
recorded in case.json). **Genuine incomplete fix; gate passed on real Docker over
EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official `grafana/loki` images (`2.2.1` / `3.6.3` / `3.6.4`), ruler enabled
with a LOCAL rule store (`/loki/rules-src`), `auth_enabled=true` so `X-Scope-OrgID`
drives the tenant input; tenant `fake` is legitimate (a benign namespace exists).
Read-exfil canary: `oracle.py` plants `/loki/pcb_flag.yaml` ONE dir above the
store — a VALID Loki ruler group whose group NAME is the per-run `${PCB_FLAG}` —
so the flag appears in the API response body only when the traversal resolves.
No app code modified; the oracle self-tears-down (`down -v --rmi all`).

Grafana's advisory (case.json `evidence.incomplete_fix_quote`): "The CVE-2021-36156
fix validates the namespace parameter for path traversal sequences after a single
URL decode, by double encoding, an attacker can read files at the Ruler API
endpoint /loki/api/v1/rules/{namespace}." `patch_real.diff` is the CVE-2021-36156
fix (commit `2fd633cded9a97c8c6b29160549a157678d1fa2f`, PR #4020, 2.3.0: restrict
`X-Scope-OrgID` path segments). Source-confirmed (provenance): `parseNamespace`
(pkg/ruler/base/api.go) has a single `url.PathUnescape` in v3.6.0/v3.6.3;
`filepath.IsLocal` is added only in v3.6.4.

Encoding arithmetic: plain or SINGLE-encoded `../` namespaces never reach the
sink — net/http percent-decodes the path and its clean-path redirect answers 301
(verified on every version); `..%252f..%252fpcb_flag.yaml` stays one segment
after net/http's single decode (no 301), then `parseNamespace`'s one
`PathUnescape` yields `../../pcb_flag.yaml`.

- **V0 = 2.2.1** (`grafana/loki:2.2.1`, `:33720`) — ORIGINAL tenant-id vector:
  `GET /loki/api/v1/rules/pcb_flag.yaml` with `X-Scope-OrgID: ..` ->
  `Join("/loki/rules-src","..","pcb_flag.yaml")` -> flag read (HTTP 200).
- **V1 = 3.6.3** (`grafana/loki:3.6.3`, `:33721`, target) — the 36156 fix BLOCKS
  the tenant-id seed (HTTP 500 "no org id"), but the double-encoded namespace
  residual with `X-Scope-OrgID: fake` -> flag read (HTTP 200). Incomplete fix.
- **V2 = 3.6.4** (`grafana/loki:3.6.4`, `:33722`, 21726 fix) —
  `filepath.IsLocal` -> HTTP 500 "invalid namespace: path traversal not allowed"
  (repro.log).

- **Original trigger**: `GET /loki/api/v1/rules/pcb_flag.yaml` with
  `X-Scope-OrgID: ..` (`poc/original_poc.py` candidate).
- **Residual trigger**: `GET /loki/api/v1/rules/..%252f..%252fpcb_flag.yaml`
  with `X-Scope-OrgID: fake` (double-encoded `../`; `_heldout/bypass_poc.py`
  candidate).

Run: `PCB_FLAG=<tok> python3 oracle.py --run-gate` (gate 2026-07-17: original
reaches@v0 / blocked@v1 / residual reaches@v1 / blocked@v2; PASSED=true). See
`repro.log` and `case.json`.

> NOTE: the advisory text says the 36156 fix "validates the namespace parameter",
> but source inspection shows the fix actually restricted the TENANT-ID input and
> v3.6.3's `parseNamespace` has no traversal check at all — INCOMPLETE_FIX_ANALYSIS.md
> and case.json `audit.note` both document this corrected mechanism (there was
> never an intermediate single-decode namespace guard).
