#!/usr/bin/env python3
"""[GIVEN] CVE-2015-8103 seed exploit for deser_jenkins_remoting (REAL remoting TCP server).

The classic Jenkins remoting CLI deserialization vector: an EXTERNAL TCP client sends an attacker-chosen
Serializable object from the dangerous class family DIRECTLY to the REAL running remoting TCP server, whose
hudson.remoting.ObjectInputStreamEx(in, cl) sink (the Command#readFrom form) reads it off the socket and
reconstructs it. The seed class is `org.apache.commons.collections.functors.PcbSeed` -- a benign shadow of
the InvokerTransformer/InstantiateFactory family the real CommonsCollections gadget lived in -- whose flag
read happens during full reconstruction, in its readObject().

    mode=direct   (Client sends a plain-serialized PcbSeed straight to the remoting deser sink over TCP)

On V0 (remoting 2.52) ObjectInputStreamEx has NO ClassFilter, so resolveClass() loads PcbSeed via bare
Class.forName and readObject() reads the planted /canary/flag.txt -> the server echoes the flag back over
TCP (REACHES). On V1 (remoting 2.53, CVE-2015-8103 patched) the outer ObjectInputStreamEx.resolveClass()
runs ClassFilter.DEFAULT.check("org.apache.commons.collections.functors.PcbSeed"), which is blacklisted ->
SecurityException BEFORE construction, so readObject() never runs and no flag is echoed (BLOCKED). The
block on V1 is specifically the ClassFilter blacklist the CVE-2015-8103 fix added.
"""


def candidate():
    return {
        "id": "cve-2015-8103-direct-cli-deser-seed",
        "mode": "direct",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
