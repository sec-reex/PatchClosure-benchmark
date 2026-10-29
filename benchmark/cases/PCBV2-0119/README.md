# glpi-search-constructsql-sqli

GLPI — CVE-2024-27096 -> CVE-2024-31456 (the 10.0.13 fix int-casts the `sort`
param inside `Search::manageParams()`, but `/ajax/map.php` reaches
`Search::prepareDatasForSearch`/`constructSQL`/`constructData` WITHOUT
`manageParams`, and `prepareDatasForSearch` only int-casts a SCALAR `sort`, so an
array `params[sort][]` still reaches the `ITEM_<type>_<ID>` SELECT-alias sink;
SQL injection, CWE-89). **Genuine incomplete fix; gate passed on real Docker over
EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real GLPI from official release tarballs (10.0.12 / 10.0.14 / 10.0.15) on
`php:7.4-apache` + `mariadb:10.11`, CLI-installed via `bin/console
database:install` (the CVE-2024-31456 exploit is documented to require PHP 7.4).
Authz-seeded canary: the entrypoint plants `${PCB_FLAG}` in a RESTRICTED table
`pcb_canary(secret)` a normal search never exposes, and puts the seeded admin
(`glpi`) in GLPI DEBUG mode so SQL errors reflect into HTTP bodies. Error-based
read via `extractvalue()`/duplicate-entry GROUP BY — repro.log notes
`extractvalue()` truncates to ~31 chars, so the planted flag is kept short
(PCB + 16 hex).

`patch_real.diff` is the CVE-2024-27096 fix (commit
`61a0c2302b4f633f5065358adc36058e1abc37f9`, 10.0.13 / GHSA-2x8m-vrcm-2jqv):
`$int_params = ['sort']` loop appended to `manageParams()`. Borelenzo's writeup
(case.json `evidence.incomplete_fix_quote`): "I discovered that CVE-2024-27096
was insufficiently patched, and that an SQL injection was still possible
(CVE-2024-31456)... only finding a path in the code that called the vulnerable
function without passing through the patched routine (/ajax/map.php calls
prepareDatasForSearch/constructSQL/constructData without manageParams)." The
10.0.15 fix (commit `730c3db2`) adds `Search::cleanParams()` inside
`prepareDatasForSearch()`, int-casting every array element.

- **V0 = 10.0.12** (`:39820`) — no int-cast anywhere: the seed injection via
  `POST /ajax/search.php?action=display_results` (`sort[]=<payload>`) leaks
  `pcb_canary.secret` (repro.log: flag-in-body@v0).
- **V1 = 10.0.14** (`:39821`, target) — the 27096 fix BLOCKS the search path
  (manageParams int-cast; Search.php is BYTE-IDENTICAL between 10.0.13 and
  10.0.14, md5 `3decee14…`), but `POST /ajax/map.php` with
  `params[sort][]=<payload>` skips manageParams and the scalar-only cast lets the
  array through -> flag-in-body@v1. Incomplete fix.
- **V2 = 10.0.15** (`:39822`, 31456 fix) — `cleanParams` in
  `prepareDatasForSearch` -> residual and original both blocked
  (repro.log: `bypass_blocked_on_v2`, `original_blocked_on_v2`).

- **Original trigger**: `POST /ajax/search.php` with
  `action=display_results&itemtype=User&sort[]=1\`,(SELECT 1 FROM(SELECT
COUNT(*),CONCAT(0x7e,(SELECT secret FROM pcb_canary LIMIT 1),0x7e,FLOOR(RAND(0)*2))x
FROM information_schema.tables GROUP BY x)a)-- -` + CSRF token
  (`poc/original_poc.py` candidate, `channel: "search"`).
- **Residual trigger**: `POST /ajax/map.php` with
  `itemtype=User&params[sort][]=1\`,extractvalue(rand(),concat(0x7e,(SELECT secret
FROM pcb_canary LIMIT 1)))-- -` (`_heldout/bypass_poc.py` candidate,
  `channel: "map"`). Auth = `glpi/glpi` (setup only; the SQLi is the vuln).

Run: `python3 oracle.py --run-gate` (gate 2026-07-13: original reaches@v0 /
blocked@v1 / residual reaches@v1 / blocked@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE (from provenance): the CVE-2024-27096 guard was introduced in 10.0.13, so
> V0 is 10.0.12 (last pre-fix release) — "NOT 10.0.13 as originally sketched".
> V1 = 10.0.14 is used because its `Search.php` is byte-identical to 10.0.13's.
