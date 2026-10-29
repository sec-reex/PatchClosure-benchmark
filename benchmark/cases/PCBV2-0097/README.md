# deser_concretecms_unserialize

Concrete CMS — CVE-2026-3452 -> CVE-2026-8135 (PHP deserialization / PHP Object Injection,
CWE-502; the `unserialize()` sink is never hardened, the fix lineage only guards the save-time
WRITE path).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (GATE PASSED, Variant A,
5/5 checks).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Concrete CMS, git-cloned at the exact tags 9.4.7 / 9.4.8 / 9.5.1 at build time
(php:8.1-apache + mariadb:10.11), installed with the real `c5:install` and seeded with a real
Express object + `express_entry_list` block via Concrete CMS APIs. Sink: the Express Entry List
block controller (`concrete/blocks/express_entry_list/controller.php`) feeds the stored
block-config values to bare `unserialize($this->columns)` / `unserialize($this->filterFields)`
with NO `allowed_classes` when the block is viewed/edited. The CVE-2026-3452 fix (9.4.8, commits
`167f16e` + `5b9dead`, PR #12826) added a save() WRITE guard — blank `columns`/`filterFields`
unless `($data['_fromCIF'] ?? null) === true` — leaving the sink itself untouched; CVE-2026-8135
(case.json quote): "A rogue administrator ... can bypass the intended protection mechanism
(_fromCIF === true) ... by leveraging the REST API functionality. Because the REST API parses
requests using json_decode(), the string \"true\" is evaluated as a strict PHP Boolean(true)."
Canary = benign shadow class `PcbFlagProbe` (`O:12:"PcbFlagProbe":0:{}`, planted autoloadable at
`/app/application/src/PcbProbe/PcbFlagProbe.php` by `pcb_seed.php`): if the REAL render-path
`unserialize()` instantiates it, its `__wakeup()` reads the planted `/canary/flag.txt`
(`${PCB_FLAG}`, outside the app dir) and echoes it. The EXTERNAL trigger is an HTTP POST to
`pcb_driver.php`, which `json_decode()`s the body (the REST-API channel), calls the REAL
cloned controller's `save($data)` guard, then its `view()` (the render-path sink); response
`flag_echoed=true` + `flag_line` `PCB_CTOR_FLAG=<token>` iff the payload survived the guard.
No gadget chain, no command execution.

- **V0 = Concrete CMS 9.4.7** (`:8080`) — `save()` does NO columns/filterFields blanking -> the
  form-POST payload is stored verbatim and the render `unserialize()` instantiates
  `PcbFlagProbe` -> flag.
- **V1 = Concrete CMS 9.4.8** (`:8081`, target; CVE-2026-3452 fix) — the save() guard blanks the
  two fields unless `_fromCIF === true`; a browser form POST can only send the STRING `"true"`,
  which fails the strict comparison -> the seed is blanked (stored_filterFields_len=6,
  flag_echoed=false) -> seed BLOCKED. But the discriminator lives INSIDE the untrusted `$data`
  array, and the REST channel's `json_decode()` turns `"_fromCIF": true` into a REAL PHP boolean
  -> the blank is SKIPPED and the payload is stored -> the residual reaches the same sink.
  Incomplete fix.
- **V2 = Concrete CMS 9.5.1** (`:8082`, CVE-2026-8135 fix) — the guard now reads
  `$this->saveMode === SaveMode::SAVE_MODE_IMPORT`, an INTERNAL controller flag set only by the
  genuine CIF-import path and NOT carryable in `$data`; a REST/front-end save has
  `saveMode='request'` -> blank always runs -> residual (and original) BLOCKED.

- **Original trigger**: form-POST channel body `{"args":{"columns":"O:12:\"PcbFlagProbe\":0:{}",
  "filterFields":"O:12:\"PcbFlagProbe\":0:{}","_fromCIF":"true"},"saveMode":"request"}` — the
  string `"true"` fails `=== true` on 9.4.8. Reaches on 9.4.7 (flag echoed), blocked on 9.4.8.
- **Residual trigger**: the SAME payload but with `"_fromCIF":true` as a JSON BOOLEAN
  (`{"args":{...,"_fromCIF":true},"saveMode":"request"}`) over the REST `json_decode()` channel —
  passes the 9.4.8 `=== true` gate, blank skipped, payload stored, render-path
  `unserialize()` instantiates `PcbFlagProbe`. Reaches on 9.4.8
  (`PCB_CTOR_FLAG=PCBFLAG_cb4c0d831188a00e9c6da2df7a8cc098`), blocked on 9.5.1.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: case.json `stale_files` (and the repro.log teardown section) lists `harness.php` — the
> old BANNED source-lift harness — but no such file exists anywhere in this case directory
> (checked with `find`); the stale-file record is outdated, and nothing in the current
> compose/oracle references it.
