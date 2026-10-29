#!/usr/bin/env python3
"""[HELD-OUT] CVE-2017-1000353 residual for deser_jenkins_remoting (REAL remoting TCP server).

CVE-2015-8103's fix added the hudson.remoting.ClassFilter blacklist to the CLI ObjectInputStream
(ObjectInputStreamEx.resolveClass -> ClassFilter.DEFAULT.check(name)). But that blacklist only inspects
the classes named in the OUTER stream. CVE-2017-1000353 wraps the dangerous object inside a
`java.security.SignedObject`:

    outer stream (ClassFilter-checked):  java.security.SignedObject   <- NOT blacklisted in remoting 2.53
    SignedObject.getObject():            new ObjectInputStream(content).readObject()  <- NO ClassFilter
        -> reconstructs org.apache.commons.collections.functors.PcbSeed -> readObject() runs

The inner ObjectInputStream that SignedObject.getObject() spins up is a PLAIN ObjectInputStream, never
wrapped by remoting's ClassFilter, so the blacklisted PcbSeed is fully reconstructed even though its name
would have been rejected in the outer stream. This is the nested-unfiltered-stream blacklist bypass.

    mode=signed   (Client sends the SAME PcbSeed wrapped in a java.security.SignedObject over TCP)

The EXTERNAL TCP client sends this to the SAME real remoting TCP server, whose outer
hudson.remoting.ObjectInputStreamEx reads it off the socket; only after the outer object is a SignedObject
does the server call getObject(), which reconstructs the inner PcbSeed via its own unfiltered stream.

Source-verified (github.com/jenkinsci/remoting): the remoting 2.53 ClassFilter.DEFAULT blacklist =
{ org.codehaus.groovy.runtime.*, org.apache.commons.collections.functors.*, *org.apache.xalan* } and does
NOT contain java.security.SignedObject. remoting 3.16 (the SignedObject-block release; the CVE-2017-1000353
SECURITY-429 fix of 2017-04-26 added SignedObject to the blacklist) adds "^java[.]security[.]SignedObject$"
to that same DEFAULT blacklist, closing the bypass.

Same real remoting server, same sink CLASS (hudson.remoting.ObjectInputStreamEx used by Command#readFrom),
same canary CLASS (PcbSeed), same rce-oob read channel (/canary/flag.txt read in readObject, echoed back
over TCP) as the seed; ONLY the wire structure changes from a direct object to a SignedObject-wrapped
object (a nested, unfiltered stream).

Contract (verified on real Docker via oracle.py, external TCP client -> real remoting server):
    * V1 = remoting 2.53 -> REACHES: the outer ObjectInputStreamEx accepts java.security.SignedObject (not
            blacklisted); SignedObject.getObject() reconstructs PcbSeed via its own unfiltered
            ObjectInputStream -> readObject() reads and the server echoes the flag (blacklist bypassed).
    * V2 = remoting 3.16 -> BLOCKED: java.security.SignedObject is on the ClassFilter blacklist, so the
            outer ObjectInputStreamEx rejects it in resolveClass() before getObject() -> no flag.

BENIGN: PcbSeed.readObject() only echoes the per-run ${PCB_FLAG} canary token; no gadget chain, no command
execution. The `signed` mode selector lives only here / in the held-out client mode, never in the GIVEN
Server or original_poc.
"""
from __future__ import annotations

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["signedobject_nested_unfiltered_stream"]


def candidate(vector: str = "signedobject_nested_unfiltered_stream"):
    return {
        "id": "cve-2017-1000353-" + vector,
        "mode": "signed",
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
