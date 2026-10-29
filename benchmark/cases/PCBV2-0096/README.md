# deno-cve-2026-32260

Deno — CVE-2026-27190 -> CVE-2026-32260 (OS command injection via incomplete shell-metacharacter
neutralization in the SAME sink, `transformDenoShellCommand()`, CWE-78).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official deno release binaries 2.6.7 / 2.7.1 / 2.7.2, installed side-by-side via the
official install.sh and selected per profile by `HARNESS_VER`, so `Deno.execPath()` is exactly
the published bytes. A minimal HTTP harness (`harness.ts`, `Deno.serve`) exposes
`GET /probe?arg=<deno CLI args string>`; it builds `<Deno.execPath()> <arg>` and runs it via
`node:child_process spawnSync(cmd, {shell:true})` — which routes through Deno's
`transformDenoShellCommand()` (`ext/node/polyfills/internal/child_process.ts`), the security
boundary that re-quotes deno CLI args "safe to embed in a shell command string". CVE-2026-32260
advisory (case.json, CVSS 8.1): its "two-stage argument sanitization ... has a priority bug: when
an argument contains a $VAR pattern it is wrapped in double quotes instead of single quotes, and
double quotes in POSIX sh do not suppress backtick command substitution... This bypasses the fix
for CVE-2026-27190." Canary = benign flag read: `entrypoint.sh` plants `${PCB_FLAG}` at
`/canary/flag.txt` (outside the app) and installs the no-arg reader `/canary/rf`
(`cat /canary/flag.txt`); a surviving backtick runs `/canary/rf` via command substitution and the
flag is observed in the deno `Module not found "<flag>"` error on stderr (on blocked versions the
LITERAL backtick, `%60`, appears instead — a sound injection oracle). No real payload.

- **V0 = deno 2.6.7** (`:39930`) — blocklist-only, NO quoting: `/[();&|<>`!]/`-matching args make
  `transformDenoShellCommand()` return the ORIGINAL command unchanged -> the plain-backtick seed's
  substitution reaches `/bin/sh` -> flag.
- **V1 = deno 2.7.1** (`:39931`, target; carries the CVE-2026-27190 fix from 2.6.8, commit
  `9132ad9`) — per-arg SHELL-QUOTING; the seed arg has no `$VAR` reference so it takes the
  SINGLE-quote branch -> backtick is literal -> seed BLOCKED. But the POSIX branch checks
  `/\$\{[^}]+\}|\$[A-Za-z_]/` FIRST and DOUBLE-quotes any `$VAR` arg to preserve expansion ->
  the `$VAR`+backtick residual still executes. Incomplete fix.
- **V2 = deno 2.7.2** (`:39932`, CVE-2026-32260 fix) — the double-quote branch is gated by
  `unsafeInDoubleQuotes = /`|\$\(|\\/`, forcing a `$VAR` arg that also contains a backtick into
  the single-quote branch -> residual BLOCKED.

- **Original trigger**: probe arg `run `/canary/rf`` (plain backtick, no `$VAR`) — V0 returns the
  command unchanged, `/bin/sh` runs the substitution -> flag in the probe `output`. Reaches on
  2.6.7, blocked on 2.7.1 (single-quoted).
- **Residual trigger**: probe arg `run $X`/canary/rf`` (`$X` steers the arg into V1's
  double-quote branch; `$X` expands to empty but the backtick still runs inside double quotes) —
  flag in the probe `output`. Reaches on 2.7.1, blocked on 2.7.2. Negative controls: `run $X`
  (no backtick) and plain `run mod.ts` stay flag-free.

Run: `python3 oracle.py --gate` (env already up; `--wait` polls v0+v1+v2 readiness first).
See `repro.log` and `case.json`.
