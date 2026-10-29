#!/usr/bin/env python3
"""[GIVEN] Original seed = CVE-2019-20920 (GHSA-3cqr-58rm-57f8).

The `lookup` helper resolves an attacker-named property with no proto-access
filtering, so an untrusted template can read a NON-OWN (prototype-chain) secret.
On handlebars 4.5.2 (V0) this reads the planted canary. On 4.7.6 (V1) the
CVE-2019-20920 fix rewrote the lookup helper to route through
`options.lookupProperty(obj, field)` (the proto-access guard), so this seed is
BLOCKED on V1 -> the differential precondition.
"""


def candidate():
    return {
        "probe_id": "original-cve-2019-20920-lookup-helper",
        # lookup helper reads the non-own prototype property `pcbCanary`
        "template": '{{lookup this "pcbCanary"}}',
        "strict": False,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
