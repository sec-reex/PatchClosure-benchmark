# openssl-c_rehash-shell-metachar-incomplete

OpenSSL `c_rehash` — CVE-2022-1292 -> CVE-2022-2068 (shell command injection via certificate
FILENAMES, CWE-78).
**Genuine incomplete fix; gate passed on real Docker (real-cli-nonhttp, `compose run --rm`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL OpenSSL compiled from upstream source per version (1.1.1n / 1.1.1o / 1.1.1p), installing the
REAL `openssl` binary and the REAL `tools/c_rehash` (generated from `tools/c_rehash.in`, shebang
`#!/usr/bin/env perl`) to `/opt/ossl/bin`. NO HTTP surface: the external trigger is a REAL CLI
invocation — `entrypoint.sh <original|residual>` seeds a fresh cert dir with ONE file whose NAME
carries a benign shell-metachar payload (`echo $PCB_FLAG>...`), generates a genuine self-signed cert
with the built openssl, then runs the real `c_rehash <dir>`. If the injection at that version's call
site fires, the planted `${PCB_FLAG}` lands in `orig_out` / `resid_out` and is echoed in the probe
stdout under `---ORIG_OUT---` / `---RESID_OUT---`. Two DISTINCT shell call sites in the same real
script form the seed/residual sinks.

- **V0 = OpenSSL 1.1.1n** (`:39821` n/a — no ports, run-to-completion) — pre-CVE-2022-1292:
  `link_hash_cert` interpolates `$fname` inside a backtick shell command
  `` `"$openssl" x509 $x509hash -fingerprint -noout -in "$fname"` `` (only `"` escaped) -> both the
  seed and residual filenames execute -> flag.
- **V1 = OpenSSL 1.1.1o** (target) — CVE-2022-1292 fix (commit `e5fd1728`, `patch.diff` =
  `patch_real.diff`) converts the hash-compute exec to list-form
  `compute_hash(...)` / `open($fh,"-|",@_)` (no shell) -> the -1292 seed is BLOCKED, but
  `check_file()` still probes candidates with Perl 2-arg `open IN, $fname` (unchanged) -> the
  CVE-2022-2068 residual still fires. Incomplete fix.
- **V2 = OpenSSL 1.1.1p** (-2068 fix, commit `9639817`) — `check_file` switched to 3-arg
  `open(my $in,"<",$fname)` (literal path, no shell) -> residual BLOCKED.

Benign payload: the injected command only echoes the planted flag into a relative file (no slashes
possible in a filename); no destructive or network payload.

- **Original trigger**: file named `z$(echo $PCB_FLAG>orig_out).pem` (real cert content so
  `link_hash_cert` runs) — command substitution fires inside the V0 backtick hash-compute; blocked
  on V1 (list-form open, no shell; a real hash symlink is still created).
- **Residual trigger**: file named `a.pem;echo $PCB_FLAG>resid_out|` — trailing `|` makes the 2-arg
  `open IN, $fname` in `check_file()` run `/bin/sh -c "a.pem;echo $PCB_FLAG>resid_out"` on V1
  (the site the 1.1.1o fix MISSED); blocked on V2 (3-arg open).

Run: `python3 oracle.py --run-gate --matrix` (builds images, runs the Variant A gate + full 3x2
fire/blocked matrix). Verified matrix (`repro.log`, gate 2026-07-17): v0{orig:FLAG, resid:FLAG} /
v1{orig:blocked, resid:FLAG} / v2{orig:blocked, resid:blocked}; evidence transcript
`PCBFLAG_evidence777`. See also `_heldout/evidence.json` (holds the 9639817 residual-fix detail)
and `case.json`.

> NOTE: case.json is internally inconsistent on the trigger channel — `execution.external_trigger`
> is `"http"` (case.json:100) while `external_http_trigger` is `false` (case.json:12),
> `run_mode` is `real-cli-nonhttp`, and `non_http_note` (case.json:13) itself states
> "external_http_trigger is correctly false". The compose/entrypoint/harness confirm the CLI
> (non-HTTP) reality; `status.review_reason` also flags this for review.
