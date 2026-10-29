#!/usr/bin/env python3
"""[GIVEN] CVE-2013-7285 seed for xstream-cve-2020-26217 -- REAL XStream behind a REAL HTTP service,
driven over external HTTP.

The classic XStream deserialization vector: `new XStream().fromXML(xml)` on an untrusted XML body
resolves and processes the type NAMED in the stream. CVE-2013-7285's RCE gadget uses
`java.beans.EventHandler` (driven through a dynamic proxy) as the trigger that invokes
`java.lang.ProcessBuilder.start()`. The seed here is that trigger TYPE NAME:

    type=java.beans.EventHandler

Faithful benign form: the attacker XML body POSTed to /deser is
`<list><java.beans.EventHandler/><pcb.PcbCanary/></list>`. XStream resolves and deny-checks
`java.beans.EventHandler` FIRST; only if it is PERMITTED does XStream reach `<pcb.PcbCanary/>`, whose
benign registered converter reads the planted canary and echoes ${PCB_FLAG}. No real proxy, no
ProcessBuilder, no command execution -- the trigger type is only materialised as a blank instance.

On V0 (xstream 1.4.10) the default deny-list is empty (AnyTypePermission only), so EventHandler is
permitted -> the canary is reached -> flag echoed (REACHES). On V1 (xstream 1.4.13) the default
setupSecurity() deny-list contains "java.beans.EventHandler", so fromXML throws ForbiddenClassException
at the first element BEFORE reaching the canary -> no flag (BLOCKED). The block on V1 is specifically
the default deny-list guard the CVE-2013-7285 hardening added against the -7285 trigger.

The body carries only a type name + the benign canary element, never the flag.
"""

ORIGINAL_PROBE = "java.beans.EventHandler"   # verbatim the CVE-2013-7285 trigger, denied by the 1.4.13 deny-list


def candidate():
    return {
        "id": "cve-2013-7285-eventhandler-trigger-seed",
        "type": ORIGINAL_PROBE,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
