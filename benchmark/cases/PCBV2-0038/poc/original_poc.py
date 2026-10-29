#!/usr/bin/env python3
"""[GIVEN] CVE-2023-6069 seed exploit for froxlor-cve-2026-41231.

The customer's SubDomains.add API is called with a docroot path `pcbseed/newout` where
$HOMEDIR/pcbseed is a symlink pointing outside the customer homedir (to the panel web
root /var/www/html/seedout). On v0 (2.0.11) FileDir::makeCorrectDir performs no symlink
resolution check, so the Apache config cron creates /var/www/html/seedout/newout/
(plus index.html) -> observable as HTTP 200 on /seedout/newout/. On v1 (2.3.5) the
CVE-2023-6069 fix (9e8f32f1) makes makeCorrectDir throw
"Found symlink pointing outside of customer home directory", so the subdomain is never
stored and the directory never appears (HTTP 404).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import seed_probe, FLAG  # noqa: E402


def candidate(*, version="v1", flag=None):
    return seed_probe(version, flag or FLAG)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
