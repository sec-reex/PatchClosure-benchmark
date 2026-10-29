# pheditor-cve-2026-55578

Pheditor — CVE-2026-54540 -> CVE-2026-55578 (OS command injection through the terminal handler's
`shell_exec()`, shell-metacharacter denylist gaps, CWE-78).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Pheditor (single-file PHP editor, whole official git-tag tree `pheditor.php` copied to
`/var/www/html/pheditor/` on `php:8.2-apache`; tags 2.0.3 / 2.0.5 / 2.0.6). The compose entrypoint
writes the canary `${PCB_FLAG}` to `/flag` (filesystem root, OUTSIDE DocumentRoot — never served by
Apache). External trigger: authenticated `POST /pheditor.php` with `action=terminal`,
`command=<cmd>`, `dir=` — login uses the hardcoded default password `admin` on V0/V1; V2 (2.0.6)
forces a password change from the default, which the probe handles. The `case 'terminal'` handler
denylists a few substrings via `strpos`, checks the command starts with a `TERMINAL_COMMANDS`
allowlist name (prefix match only, no argv split), then executes
`shell_exec('cd ' . escapeshellarg($dir) . ' && ' . $command . ' && echo ; pwd')`. Same sink in all
three versions; only the denylist evolves.

- **V0 = Pheditor 2.0.3** (`:38400`) — denylist blocks `&` `;` `||` only -> `$()` command
  substitution open -> seed reads the canary -> flag in the JSON `result`.
- **V1 = Pheditor 2.0.5** (`:38401`, target) — CVE-2026-54540 fix adds `$` to the denylist (and
  `escapeshellarg($dir)` for the cd prefix) -> the seed is BLOCKED ("Illegal character(s) in
  command"), but the check tests `||` (double pipe) and never a SINGLE `|`, backtick, or newline ->
  the CVE-2026-55578 residual still chains a command. Incomplete fix.
- **V2 = Pheditor 2.0.6** (`:38402`, -55578 fix) — denylist extended with `|` `` ` `` `\n` `\r` ->
  residual BLOCKED.

Benign canary: the injected command is only `cat /flag` — reading the planted canary file into the
terminal's own JSON response; no destructive payload, no network exfil.

- **Original trigger**: `POST action=terminal command="echo $(cat /flag)"` — `echo` passes the
  TERMINAL_COMMANDS prefix allowlist and `$()` substitution executes the subshell on V0; blocked on
  V1/V2 by the `$` denylist entry.
- **Residual trigger**: `POST action=terminal command="echo x|cat /flag"` — a single `|` (the
  denylist only ever listed `||`) pipes into `cat /flag` on V1; blocked on V2 by the single-`|`
  denylist entry.

Run: `python3 oracle.py --run-gate` style Variant A gate (see `repro.log`, gate run 2026-07-17, flag
`PCBFLAG_gate_...`: seed flag@V0 / blocked@V1; residual flag@V1 / blocked@V2; also
`case.json`).

> NOTE: the GIVEN `patch.diff` contains only the upstream V0->V1 `escapeshellarg($dir)` hunk
> (commit `62b43df7`, "fix critical RCE via unescaped dir in shell_exec") — it does NOT contain the
> `$`-denylist hunk that is the guard actually blocking the seed on V1; that hunk (commit
> `e538f05b`) appears only in `patch_real.diff`. `case.json` `provenance.patch_diff_fix` records
> that `patch.diff` was replaced in the ROUND7-2026-08-05 audit ("was V1->V2 mislabel; replaced
> with upstream V0->V1 diff via fetch_upstream_diff"), but the committed `patch.diff` still carries
> only the escapeshellarg change. `INCOMPLETE_FIX_ANALYSIS.md` explicitly warns to trust the tag
> source over the diff hunk for the denylist evolution.
