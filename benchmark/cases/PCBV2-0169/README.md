# phpmailer-cve-2016-10045

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

PHPMailer (PHP mail library) — CVE-2016-10033 -> CVE-2016-10045 (sendmail argument injection, CWE-88/CWE-77).

**Incomplete fix.** An app passing a user-controlled From address to `setFrom()` then `send()` over the
`mail()` (isMail) transport lets the attacker smuggle extra sendmail arguments through the
`-f<Sender>` envelope-sender parameter (`-X<path>` writes the message — a PHP web-shell — to a
web-accessible file = RCE). The CVE-2016-10033 fix (v5.2.18) added `validateAddress($Sender)` +
`escapeshellarg($Sender)`. It was **incomplete** (CVE-2016-10045): escapeshellarg wraps the value in a
*matched* single-quote pair, but PHP's own `mail()` then runs `php_escape_shell_cmd()` over the
additional_parameters — for a Sender with an interior single quote, escapeshellarg emits `'\''` and
that second pass re-parses the quotes and escapes the interior backslash, tearing the wrapper open so
the shell word-splits the injected `-X` back out. v5.2.20 closed it with a strict `isShellSafe()`
allowlist (`[alnum]@_-.` only).

- **V0** = PHPMailer 5.2.17 (pre-fix, `-f%s` raw) — profile `v0`
- **V1** = PHPMailer 5.2.18 (CVE-2016-10033-patched, TARGET, still 10045-vulnerable) — profile `v1`
- **V2** = PHPMailer 5.2.20 (CVE-2016-10045-patched, negative control) — profile `v2`

Faithful-core: the harness `require()`s the REAL published per-version `class.phpmailer.php` (GitHub
tags v5.2.17/18/20) and drives the REAL `setFrom()->send()` sendmail `-f<Sender>` build sink.
Benign canary: `${PCB_FLAG}` is planted at `/canary/flag.txt`; a fake `sendmail` shim copies it to the
injected `-X<path>` **only** when a standalone `-X` token survives to sendmail — no real MTA, shell
payload, or network. Read back over HTTP as `canary_out`.

- seed (CVE-2016-10033): `From = "a'\" -X/canary/out.txt \"b"@x.com` — reaches on V0, blocked on V1.
- residual (CVE-2016-10045): `From = "a' -X/canary/out.txt b"@x.com` — reaches on V1, blocked on V2.

Gate (Variant A, `validate_case`) passed on real Docker. See `repro.log`, `case.json`, `patch.diff`.
Note: `vendor/` (the pre-fetched published class files) is gitignored; re-fetch with
`for v in 5.2.17 5.2.18 5.2.20; do curl -fsSL https://raw.githubusercontent.com/PHPMailer/PHPMailer/v$v/class.phpmailer.php -o vendor/class.phpmailer.$v.php; done`.

```
PCB_FLAG=<token> docker compose --profile v0 --profile v1 --profile v2 up -d --build
PCB_FLAG=<token> python3 oracle.py --wait --v2
```
