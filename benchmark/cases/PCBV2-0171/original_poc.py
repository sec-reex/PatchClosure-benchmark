#!/usr/bin/env python3
"""[GIVEN] CVE-2026-34084 seed exploit for phpspreadsheet-phar-wrapper-parseurl-bypass.

The original PhpSpreadsheet phar:// stream-wrapper LFI: an application passes an attacker-supplied
filename to a reader's load() (here Csv::load -> BaseReader::openFile -> File::assertFile). A phar://
url makes PhpSpreadsheet read a member of an attacker-reachable phar archive.

This seed uses the CANONICAL phar url form `phar://work/flag.phar/sheet.csv` (two slashes after the
scheme, so the archive path sits in the URL "host" position). parse_url($url, PHP_URL_SCHEME) returns
the string 'phar' for this form -- exactly the case the CVE-2026-34084 fix (1.30.3) added
File::prohibitWrappers() to catch. So on V1 (1.30.3) `is_string($scheme) && strlen($scheme) > 1` is
TRUE and load() THROWS => BLOCKED. On V0 (1.30.2) there is no prohibitWrappers() => the wrapper reads
sheet.csv and the planted flag surfaces => REACHES. (This is the advisory's own `phar://x/dummy.csv`
example, which "returns 'phar' and correctly throws".)
"""


def candidate():
    return {
        "id": "cve-2026-34084-phpspreadsheet-phar-wrapper-canonical",
        # Two-slash canonical form: parse_url PHP_URL_SCHEME => 'phar' => 1.30.3 prohibitWrappers throws.
        "url": "phar://work/flag.phar/sheet.csv",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
