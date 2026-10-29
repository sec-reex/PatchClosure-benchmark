#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-26217 residual for xstream-cve-2020-26217 -- REAL XStream behind a REAL HTTP
service, driven over external HTTP.

CVE-2013-7285's hardening put the -7285 trigger `java.beans.EventHandler` on XStream's DEFAULT deny-list
(XStream.setupSecurity(), applied by `new XStream()`; present by 1.4.13). That deny-list is INCOMPLETE
(CWE-184): it enumerates only a handful of known trigger names, so any OTHER type that reaches the same
fromXML() RCE sink still deserializes out of the box. The advisory (CVE-2020-26217,
x-stream.github.io/CVE-2020-26217.html): it "is a variation of CVE-2013-7285", affects "all versions
until and including 1.4.13 ... out of the box", fixed in 1.4.14.

Confirmed against the V1 (1.4.13) default deny-list: setupSecurity() denies "java.beans.EventHandler"
(+ regexps .*$LazyIterator and javax.crypto.*) but does NOT deny
`javax.imageio.ImageIO$ContainsFilter` -- the NEW trigger type the CVE-2020-26217 chain uses to invoke
the target method, which XStream 1.4.14 ADDS to the default deny-list. So the residual POSTs the SAME
kind of benign XML body to the SAME real endpoint (POST /deser) but naming that off-1.4.13-deny-list
type ('$' -> '_-' per XStream's default nested-class element naming):

    <list><javax.imageio.ImageIO_-ContainsFilter/><pcb.PcbCanary/></list>

  * V1 = 1.4.13 (CVE-2013-7285 patched): the name is NOT in the default deny-list -> XStream PERMITS it
    -> fromXML processes it and reaches <pcb.PcbCanary/> -> its converter reads /canary/flag.txt -> flag
    echoed (RESIDUAL REACHES on V1, past the -7285 fix -- the enumerated deny-list is incomplete).
  * V2 = 1.4.14 (CVE-2020-26217 patched): the name is now in the default deny-list -> fromXML throws
    ForbiddenClassException BEFORE reaching the canary -> no flag (BLOCKED). This deny-list extension is
    exactly the CVE-2020-26217 remediation that superseded the narrow -7285 enumeration.

Same sink (the service's REAL new XStream().fromXML() -> the version's own default deny-list, loaded from
the pinned jar) and same canary channel (the service echoes the CanaryHolder token once <pcb.PcbCanary/>
is reached past the deny-list) as the seed; only the trigger type NAME moves from an on-1.4.13-deny-list
name to the residual off-deny-list name. BENIGN: the request body carries only type names + the benign
canary element; no gadget chain, no ProcessBuilder, no dynamic proxy, no JNDI/RMI, no command execution.
"""
from __future__ import annotations

RESIDUAL_PROBE = "javax.imageio.ImageIO$ContainsFilter"

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["imageio_containsfilter_not_on_7285_denylist"]


def candidate(vector: str = "imageio_containsfilter_not_on_7285_denylist"):
    return {
        "id": "cve-2020-26217-" + vector,
        "type": RESIDUAL_PROBE,   # -26217 trigger, off the 1.4.13 deny-list, added in 1.4.14
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
