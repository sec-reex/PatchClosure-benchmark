# wegia-cve-2025-58745

WeGIA — CVE-2025-22133 -> CVE-2025-58745 (the 22133 fix is a finfo
`FILEINFO_MIME_TYPE` allowlist of the two Excel MIME types ONLY; the file is
still stored under the web-reachable `html/socio/sistema/tabelas/` KEEPING its
attacker-chosen extension, so an xlsx-magic-byte PHP polyglot passes the allowlist
and executes; arbitrary file upload -> RCE, CWE-434 / CWE-94). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real WeGIA git-cloned at build time at real release tags (3.4.10 for V0/V1,
3.4.11 for V2) on `php:8.2-apache` + `mariadb:10.11`, installed via WeGIA's own
BD/*.sql; driven as a seeded admin (`cpf=admin`, `senha=sha256('wegia')`,
`permissao(...,4,3)`) through the REAL upload endpoint
`POST /html/socio/sistema/controller/controla_xlsx.php` (field `arquivo`); stored
files keep the attacker extension (`<uniqid>_shell.php`) in `tabelas/` (no
PHP-exec block). RCE canary: `${PCB_FLAG}` at `/flag/pcb_flag.txt` OUTSIDE the
docroot; the payload echoes `'PCBEXEC:'.file_get_contents('/flag/pcb_flag.txt')`,
so the flag surfaces only via genuine PHP execution.

GHSA-hq96-gvmx-qrwp (case.json `evidence.incomplete_fix_quote`): "The code just
check MIME type but not validate the extension and the real content of file at
endpoint /html/socio/sistema/controller/controla_xlsx.php, which can be bypassed
by using magic bytes of Excel file in a PHP file." `patch_real.diff` is the
CVE-2025-22133 fix (commit `a08f04de…` on 3.2.8, in-tree via commit `01182db`).
The CVE-2025-58745 fix (commit `ae5a1cbf`, 3.4.11) DELETES `controla_xlsx.php`
entirely.

V0 construction (per provenance, mirroring the qdpm pattern): identical 3.4.10
code with the finfo MIME guard neutralised at boot (`NEUTRALISE_MIME_GUARD=1`) to
model the pre-22133 state; no business code modified.

- **V0 = 3.4.10, guard neutralised** (`:39480`) — plain `shell.php` accepted,
  stored, and a direct GET EXECUTES it -> canary (repro.log: reaches).
- **V1 = 3.4.10 stock** (`:39481`, target) — the 22133 finfo allowlist BLOCKS the
  plain-PHP seed (finfo -> text/x-php -> HTTP 400), but the residual uploads a
  structurally-valid OOXML package + appended `<?php ... ?>` (finfo ->
  `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`,
  allowlisted) stored as `<uniqid>_shell.php`; GET emits the zip bytes then
  EXECUTES the payload -> flag. Incomplete fix.
- **V2 = 3.4.11** (`:39482`, 58745 fix) — endpoint deleted: both uploads 404,
  nothing stored (repro.log).

- **Original trigger**: upload `shell.php` with the plain PHP body reading
  `/flag/pcb_flag.txt`, then GET the stored file
  (`poc/original_poc.py` candidate, `mode: "plain"`).
- **Residual trigger**: upload `shell.php` whose bytes are `<valid xlsx package> + <?php ... ?>`
  (`_heldout/bypass_poc.py` candidate, `mode: "xlsx_polyglot"`,
  `POLYGLOT_PHP = _xlsx() + PHP`), then GET the stored file.

Run: `python3 oracle.py --gate` (gate 2026-07-11, flag
`PCBFLAG_607e5c437b5b6b410c6386c0274dc4fb`: original reaches@v0 / blocked@v1 /
bypass reaches@v1; passed=true; V2 negative: both uploads 404). See `repro.log`
and `case.json`.
