# dbi-cve-2026-14739

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

CVE-2026-10879 -> CVE-2026-14739 (incomplete-fix chain, preparse heap overflow, DoS).

- V0 = DBI 1.647 (preparse output buffer `strlen(statement)*3`; overflow from ~1.1K placeholders)
- V1 = DBI 1.648 (CVE-2026-10879 fix: buffer `strlen(statement)*6+16`; still overflows for ~1.2M placeholders) <- target
- V2 = DBI 1.650 (CVE-2026-14739 fix: buffer factor 7 + hard limit of 99999 placeholders)

Note: the task brief attributed the 10879 fix to 1.649; source verification
shows the fix landed in **1.648** (ChangeLog) and 1.649 has an identical
`DBI.xs` (doc-only re-release). V1 = 1.648.

## Mechanism

`preparse()` (DBI.xs) expands each `?` placeholder into `:p<idx>` (up to
~9 bytes for 7-digit indexes) into a destination buffer allocated as
`strlen(statement)*F + 16`. With a statement of N bare `?` characters:

- F=3 (<=1.647): expansion exceeds the buffer from N ~= 1,100 -> heap
  corruption -> SIGABRT/SIGSEGV.
- F=6 (1.648/1.649): covers `:p1`..`:p11106` (upstream comment); ~1.2M
  placeholders produce ~10.4MB of output into a ~7.2MB buffer -> corruption
  -> SIGABRT/SIGSEGV (CVE-2026-14739).
- F=7 + `idx >= 99999` check (1.650): a clean DBI error
  ("preparse found more than 99999 '?' placeholders. Limit exceeded.") is
  returned instead of overflowing.

## Probe (Variant C, dos-threshold)

`probe.pl <N>` connects to DBD::ExampleP and calls
`$dbh->preparse("?" x N, 0x200, 0x100|0x200)` (ps_return=:pN style,
ps_accept='?'/':N'). Pre-registered crash threshold: the probe perl process
is killed by a signal (exit code >= 128, not perl-die 255). After a crash,
`verify.sh` reads `/pcb_flag.txt` (written at start from `PCB_FLAG`) and
exits 0 only if that string equals the current `RUN_FLAG`. A wrong/stale
override therefore cannot match the start-time token.

- seed: N=5,000 -> V0 crashes (134, "malloc(): invalid size (unsorted)");
  V1 exits 0 with "ok len=28893".
- residual: N=1,200,000 -> V1 crashes (134, "double free or corruption
  (out)"; 139 observed at some sizes); V2 exits 0 with the clean limit error.

## Gate

Four edges verified in real Docker (perl:5.40-bookworm + cpanm DBI@version):
seed@V0 crash, seed@V1 clean, residual@V1 crash, residual@V2 clean. See
repro.log.
