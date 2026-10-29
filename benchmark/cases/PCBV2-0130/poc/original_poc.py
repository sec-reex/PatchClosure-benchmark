#!/usr/bin/env python3
"""[GIVEN] CVE-2025-27622 (SECURITY-3495) seed -- retrieve an agent's encrypted secret
via the config.xml READ path over EXTERNAL HTTP.

The defended resource is agent "agentA" whose config.xml carries a genuine hudson.util.Secret
holding ${PCB_FLAG} (the version-exact controller encrypts it at boot; see init.groovy.d).
The attacker is a low-priv user with Agent/ExtendedRead (Computer.EXTENDED_READ) but NOT
Agent/Configure -- exactly the predicate in advisory 2025-03-05.

Real external-HTTP request (oracle run_probe drives it as user "attacker", basic auth):
    GET /computer/agentA/config.xml
The real sink -- hudson.model.Computer.doConfigDotXml:
    checkPermission(EXTENDED_READ);
    String xml = XSTREAM2.toXMLUTF8(node);
    if (hasPermission(CONFIGURE)) return xml;
    else return ExtendedReadRedaction.applyAll(xml);   // else-branch ADDED by CVE-2025-27622

Contract (verified on real Docker via oracle.py):
    * V0 = Jenkins 2.492.1 -> read path NOT redacted -> attacker receives the unredacted
                             encrypted secret; the oracle decrypts it to ${PCB_FLAG}. REACHES.
    * V1 = Jenkins 2.492.2 -> CVE-2025-27622 fix redacts the read path for non-Configure users
                             -> the secret becomes `********`; nothing to decrypt. BLOCKED.

${PCB_FLAG} is injected at run time; it appears nowhere in this file or in Jenkins source.
"""
from __future__ import annotations


def candidate() -> dict:
    """The CVE-2025-27622 read probe: fetch agentA's config.xml as the low-priv attacker."""
    return {"id": "cve-2025-27622-config-xml-read", "probe": "read"}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
