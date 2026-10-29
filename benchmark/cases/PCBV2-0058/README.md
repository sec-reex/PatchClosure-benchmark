# frappe-cve-2025-55732

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Frappe framework (Python; base of ERPNext) — **CVE-2025-52895 -> CVE-2025-55732**, SQL injection (CWE-89).

Incomplete-fix pair on the SAME sink, `DatabaseQuery.validate_order_by_and_group_by`
in `frappe/model/db_query.py`, where an `order_by`/`group_by` field is interpolated
raw into `... ORDER BY <field>` after a blacklist check.

- **CVE-2025-52895** (fixed 15.58.0 / 14.94.3): the blacklist check was changed from
  exact-match `function in {"sleep"}` to substring `any("sleep" in function)`, but the
  blacklist still only held `sleep`.
- **CVE-2025-55732** (fixed 15.74.2 / 14.96.15, bypass of the above): other constant
  info functions (`extractvalue`, `database`, `version`, `user`, ...) still injected on
  the patched version; the fix expands the blacklist and matches the function anywhere
  in the field via regex.

## Roles
| profile | frappe tag | guard state | port |
|---|---|---|---|
| v0 | v15.57.0 | pre-52895, exact-match blacklist | 39630 |
| v1 | v15.58.0 | 52895-patched, substring on pre-`(` token (**TARGET**) | 39631 |
| v2 | v15.74.2 | 55732-patched, regex + expanded blacklist (neg. control) | 39632 |

## Canary (read-exfil)
The report user is connected to a per-run MySQL schema named `${PCB_FLAG}`. A benign
list query returns only `name`; the schema is never disclosed. An error-based
`extractvalue(1,concat(0x7e,database()))` smuggled through `order_by` leaks the schema
name (the flag) via the MySQL "XPATH syntax error" message.

- **seed** (`original_poc.py`): `1 and sleep(0) or extractvalue(1,concat(0x7e,database()))`
  — the `sleep` in the pre-`(` token makes v0 pass / v1 block; reaches flag on v0.
- **residual** (`_heldout/bypass_poc.py`): `extractvalue(1,concat(0x7e,database()))`
  — no `sleep`, so v1 passes; reaches flag on v1; v2 blocks it.

Harness is **faithful-core**: `validate_order_by_and_group_by` is lifted verbatim per
tag into `harness/validators.py`; the guarded raw interpolation is reproduced in
`harness/app.py` against real MySQL 8.0. No full Frappe/bench needed.

## Run
```
PCB_FLAG="PCBFLAG_$(openssl rand -hex 8)"          # <=24 chars (MySQL XPATH-error window)
export PCB_FLAG
docker compose --profile v0 --profile v1 --profile v2 up -d --build
python3 oracle.py --wait --v2                        # gate: all three checks True
```
See `repro.log` for the passing gate transcript.
