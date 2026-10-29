#!/usr/bin/env python3
"""[HELD-OUT] CVE-2016-10045 residual exploit -- the incomplete-fix bypass of PHPMailer 5.2.18.

The CVE-2016-10033 fix (5.2.18) wraps the envelope sender in `escapeshellarg()`:

    if (!empty($this->Sender) and $this->validateAddress($this->Sender)) {
        $params = sprintf('-f%s', escapeshellarg($this->Sender));
    }

escapeshellarg() wraps the value in a matched pair of single quotes, which normally makes it one
inert argument. But PHP's own `mail()` then applies `php_escape_shell_cmd()` to the additional
parameters before handing them to the shell (the "improper interaction between the escapeshellarg
function and internal escaping performed in the mail function" the CVE-2016-10045 advisory names).

The bypass: embed a SINGLE QUOTE in the address. escapeshellarg turns each interior `'` into the
`'\''` sequence; php_escape_shell_cmd's quote-matching then re-parses those quotes and escapes the
interior backslash, tearing the wrapper open so the shell word-splits again. A valid RFC5322
quoted-local-part address carrying both a single quote and a `-X<path>` token:

    "a' -X/canary/out.txt b"@x.com

passes validateAddress() (default 'pcre8' RFC5322 validator), survives to the sink, and re-emerges
as a standalone `-X/canary/out.txt` sendmail argument on V1 -> the benign shim copies the planted
${PCB_FLAG} there. The seed's plain double-quote form is neutralised by escapeshellarg on V1, but
this single-quote form is NOT -> confirmed incomplete fix.

On V2 (PHPMailer 5.2.20, the CVE-2016-10045 fix) `isShellSafe()` rejects any Sender containing a
character outside `[alnum]@_-.` (quotes and spaces included), so `$params` is never built and no
`-f` reaches sendmail -> the residual is closed (negative control).
"""
from __future__ import annotations


def candidate() -> dict:
    return {
        "probe_id": "residual-cve-2016-10045-singlequote-escapeshellarg-bypass",
        "from": '"a\' -X/canary/out.txt b"@x.com',
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
