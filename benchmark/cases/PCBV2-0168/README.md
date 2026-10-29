# php-interpreter-cve-2024-2756

PHP (interpreter) — CVE-2022-31629 -> CVE-2024-2756 (the 8.1.11 fix discards
cookie names that mangle into `__Host-`/`__Secure-` right AFTER the first
`.`/` `->`_` mangling loop, but BEFORE the unclosed-`[` array path restores
`[`->`_`, so a raw cookie named `_[Host-flag` still lands in the protected
`__Host-` slot; improper $_COOKIE name handling, CWE-20). **Genuine incomplete
fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real PHP interpreter (official `php:8.1.10` / `8.1.11` / `8.1.28`-cli images,
built-in `php -S` server, tiny reflector app bind-mounted read-only — no
interpreter code modified). The sink is `main/php_variables.c ::
php_register_variable_ex()` cookie-name mangling. Reflection-collision canary:
NO flag is planted in the container — the per-run `${PCB_FLAG}` is the
ATTACKER-INJECTED cookie VALUE, sent over a RAW socket (exact Cookie bytes, no
client normalization); the app reflects only the protected slot
`$_COOKIE['__Host-flag']`, and the oracle detects the flag there iff a
non-`__Host-` raw cookie name mangles into `__Host-flag` — defeating the browser
cookie-prefix rule.

GHSA-wpj3-hf5j-x4v4 (case.json `evidence.incomplete_fix_quote`): "Due to an
incomplete fix to CVE-2022-31629, network and same-site attackers can set a
standard insecure cookie in the victim's browser which is treated as a __Host- or
__Secure- cookie by PHP applications. ... cookies starting with `_[Host-` are
parsed by PHP applications as `__Host-`." `patch_real.diff` is the CVE-2022-31629
first-fix (commit `0611be4e…`, bug #81727). The CVE-2024-2756 fix (php 8.1.28)
moves the check into `php_is_forbidden_variable_name()` at the plain_var
insertion point on the FINAL name.

- **V0 = 8.1.10** (`php:8.1.10-cli`, `:39810`) — no forbidden-name check:
  `Cookie: ..Host-flag=<flag>` (dots -> `_`) collides -> flag in the protected
  slot (repro.log: `"collision":true`).
- **V1 = 8.1.11** (`php:8.1.11-cli`, `:39811`, target) — the 31629 check BLOCKS
  the dot-form seed (`"collision":false`), but `Cookie: _[Host-flag=<flag>`:
  the early check runs on the `[`-truncated name `"_"`, then the array path
  finds no `]`, restores `[`->`_`, and inserts the scalar `__Host-flag` -> flag
  in the protected slot. Incomplete fix.
- **V2 = 8.1.28** (`php:8.1.28-cli`, `:39828`, 2756 fix) — check on the final
  name -> both `..Host-flag` and `_[Host-flag` discarded (`"collision":false`,
  repro.log).

- **Original trigger**: raw `Cookie: ..Host-flag=<PCB_FLAG>`
  (`poc/original_poc.py` `COOKIE_NAME = "..Host-flag"`).
- **Residual trigger**: raw `Cookie: _[Host-flag=<PCB_FLAG>` (unclosed bracket;
  `_heldout/bypass_poc.py` `COOKIE_NAME = "_[Host-flag"`; advisory PoC
  `curl -b '_[Host-x=y'` -> `{"__Host-x":"y"}`).

Run: `python3 oracle.py --gate` (gate 2026-07-13, flag
`PCBFLAG_97cdc86b015f0c47858035d5`: original reaches@v0 / blocked@v1 / bypass
reaches@v1 / both blocked@v2; passed=true, EXIT=0). See `repro.log` and
`case.json`.

> NOTE: per INCOMPLETE_FIX_ANALYSIS.md, `scripts/verify.sh --residual` merely
> re-runs `original_poc.py` (seed cookie `..Host-flag`), which is NOT the
> CVE-2024-2756 residual — the genuine residual vector is `_heldout/bypass_poc.py`'s
> `_[Host-flag`, which is what the gate (oracle.py --gate) exercises.
