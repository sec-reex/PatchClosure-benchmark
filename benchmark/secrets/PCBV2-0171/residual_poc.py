#!/usr/bin/env python3
"""[RESIDUAL] CVE-2026-45034 residual for phpspreadsheet-phar-wrapper-parseurl-bypass.

Patch bypass of CVE-2026-34084 (GHSA-87m4-826x-3crx). The 1.30.3 fix, File::prohibitWrappers(),
detects wrappers with parse_url($filename, PHP_URL_SCHEME) and rejects when the scheme is a string
of length > 1. But when the phar url has THREE (or more) slashes after the scheme -- an ordinary
way to reference an ABSOLUTE archive path -- parse_url returns boolean false instead of the scheme
string; `is_string($scheme)` is then false, no exception is thrown, yet PHP's stream layer still
honours the phar wrapper.

Residual url: `phar:///work/flag.phar/sheet.csv` (three slashes -> absolute archive /work/flag.phar).
  - V1 (1.30.3): parse_url(PHP_URL_SCHEME) => false => prohibitWrappers does NOT throw => the
    wrapper reaches load() => sheet.csv is read => planted flag surfaces => REACHES on V1.
  - V2 (1.30.5): replaced with `Preg::isMatch('~^phar://~i', ...)` which matches => THROWS => blocked.
"""


def candidate():
    return {
        "id": "cve-2026-45034-phpspreadsheet-phar-parseurl-3slash-bypass",
        "url": "phar:///work/flag.phar/sheet.csv",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
