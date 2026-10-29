#!/usr/bin/env python3
"""[GIVEN] CVE-2021-26295 seed exploit for deser_ofbiz_xmlrpc.

The real Apache OFBiz service-engine XML deserialization vector: an untrusted serialized Java object is
delivered inside an OFBiz `<cus-obj>` element (hex-encoded) in the SOAP body of an unauthenticated
request to POST /webtools/control/SOAPService. OFBiz's SOAPEventHandler feeds it through
SoapSerializer -> XmlSerializer.deserializeCustom -> UtilObject.getObject -> SafeObjectInputStream, whose
resolveClass class-name FILTER decides whether the class is resolved and instantiated (the deser sink).

Here the object is the benign shadow-class `com.pcb.java.rmi.server.PcbFlagProbe` -- a stand-in for a
"dangerous" java.rmi.server-family class that the CVE-2021-26295 fix (17.12.06) added to the blocklist.
No real gadget, no exec: its readObject merely echoes the planted ${PCB_FLAG} canary IF the running
OFBiz's real SafeObjectInputStream lets the name through.

  V0 (17.12.05): no rmi blocklist; allowlist "java..*" (regex .find) matches "java.rmi.server" -> ALLOWED
                 -> readObject reads /canary/flag.txt -> flag echoed (REACHES).
  V1 (17.12.06, CVE-2021-26295 fix): resolveClass -> className.contains("java.rmi.server") -> return null
                 -> deserialization fails before readObject -> flag never appears (BLOCKED).
"""

ORIGINAL_CANARY = "com.pcb.java.rmi.server.PcbFlagProbe"
# Precomputed standard Java serialization of a fieldless `implements Serializable` instance with
# serialVersionUID=1L for the class above (stream carries only the benign class NAME + SUID; no data,
# no gadget). Hex, as OFBiz's <cus-obj> expects (StringUtil.fromHexString).
ORIGINAL_HEX = ("ACED000573720024636F6D2E7063622E6A6176612E726D692E7365727665722E"
                "506362466C616750726F626500000000000000010200007870")


def candidate():
    return {
        "id": "cve-2021-26295-java-rmi-server-seed",
        "canary_class": ORIGINAL_CANARY,   # name carries the "java.rmi.server" substring the 06 fix blocks
        "payload_hex": ORIGINAL_HEX,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
