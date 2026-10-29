#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-30128 residual for deser_ofbiz_xmlrpc.

CVE-2021-26295's fix (17.12.06) added a class-name BLOCKLIST to SafeObjectInputStream.resolveClass:
    if (className.contains("java.rmi.server")) { ...; return null; }
run before the allowlist check. That blocklist is INCOMPLETE. As the Ridge Security analysis of the
OFBiz deserialization chain states verbatim: "If the class name is xxx.java.xxx, it will also pass the
whitelist check." OFBiz's allowlist is applied with a regex .find() (unanchored substring match), so the
permissive "java..*" pattern matches ANY class name that merely CONTAINS "java" + a char -- including a
name where "java" appears mid-package (xxx.java.xxx). And the 17.12.06 blocklist only catches the narrow
literal "java.rmi.server", so other RMI-family names (java.rmi.registry, ...) sail past it.

This residual delivers the SAME benign probe as the seed over the SAME real endpoint (POST
/webtools/control/SOAPService, <cus-obj>), but with the class name `com.pcb.java.rmi.registry.PcbFlagProbe`,
which embodies BOTH residual flaws at once:
  * xxx.java.xxx allowlist-.find() flaw: "java." appears mid-name (com.pcb.JAVA.rmi.registry...) so the
    "java..*" allowlist pattern matches though it is NOT a real java.* class;
  * narrow-blocklist gap: it is an RMI-family name NOT under "java.rmi.server", so V1's
    contains("java.rmi.server") blocklist misses it.

Real-source facts:
  * V1 = 17.12.06: resolveClass -> not contains("java.rmi.server") (miss) -> allowlist "java..*".find()
    matches -> ObjectType.loadClass -> instantiated -> readObject reads /canary/flag.txt -> flag echoed
    (RESIDUAL REACHES).
  * V2 = 17.12.07: resolveClass iterates DEFAULT_DENYLIST {"rmi","<"}: className.contains("rmi") true ->
    throw InvalidClassException BEFORE the allowlist/loadClass -> readObject never runs -> no flag
    (BLOCKED). This broad "rmi" denyList is the CVE-2021-30128/29200 remediation that superseded the
    narrow "java.rmi.server" blocklist.

Same sink (the running OFBiz's SafeObjectInputStream.resolveClass) and same read-exfil channel as the
seed; only the class NAME moves from java.rmi.server to java.rmi.registry. BENIGN: the shadow class only
echoes the per-run ${PCB_FLAG}; no gadget chain, no RMI/JNDI, no command execution.
"""
from __future__ import annotations

RESIDUAL_CANARY = "com.pcb.java.rmi.registry.PcbFlagProbe"
# Precomputed standard Java serialization (fieldless Serializable, SUID=1L) of the class above. Hex.
RESIDUAL_HEX = ("ACED000573720026636F6D2E7063622E6A6176612E726D692E72656769737472792E"
                "506362466C616750726F626500000000000000010200007870")

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["java_rmi_registry_xxx_java_xxx"]


def candidate(vector: str = "java_rmi_registry_xxx_java_xxx"):
    return {
        "id": "cve-2021-30128-" + vector,
        "canary_class": RESIDUAL_CANARY,   # xxx.java.xxx name; RMI-family but not java.rmi.server
        "payload_hex": RESIDUAL_HEX,
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
