#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-42778 static-initializer-before-allowlist residual (REAL MINA TCP server).

CVE-2024-52046's fix added a class allowlist (acceptMatchers / ClassNameMatcher, default-deny, accept()
API) to AbstractIoBuffer.getObject(). That allowlist blocks a non-allowlisted class -- but ONLY in
resolveClass(), which runs AFTER the decoder's readClassDescriptor() has already RESOLVED (and thereby
INITIALIZED) the class. The advisory (CVE-2026-42778): "The classname allowlist ... was applied too late
after a static initializer in a class to be read might already have been executed."

Confirmed in the V1 (2.2.4) source (AbstractIoBuffer.getObject inner ObjectInputStream):

    protected ObjectStreamClass readClassDescriptor() ... {
        int type = read();
        switch (type) {
            case 1: // Serializable class
                String className = readUTF();
                Class<?> clazz = Class.forName(className, true, classLoader);  // <-- initialize=TRUE, NO allowlist
                return ObjectStreamClass.lookup(clazz);
        }
    }
    protected Class<?> resolveClass(ObjectStreamClass desc) ... {   // <-- allowlist enforced only HERE, later
        ... for (matcher : acceptMatchers) if (matcher.matches(className)) return clazz;
        throw new ClassNotFoundException();
    }

So merely RESOLVING the class name from the stream runs its static initializer, before resolveClass()
ever consults acceptMatchers. The residual sends the SAME normal MINA type-1 wire as the seed, but a
class whose observable effect is in its STATIC INITIALIZER (PcbCanary) rather than in readObject()
(PcbSeed). The external TCP client fully controls the wire; nothing else differs -- same real MINA
server, same getObject() sink, same rce-oob canary file.

    mode=canary   (Client sends PcbCanary as a normal MINA type-1 descriptor over TCP)

Contract (verified on real Docker via oracle.py, external TCP client -> real MINA server):
    * V1 = mina-core 2.2.4 -> REACHES: readClassDescriptor() runs Class.forName("PcbCanary", true) ->
            PcbCanary's static initializer reads the canary into Beacon, BEFORE resolveClass() rejects the
            (non-allowlisted) class -> the server's exceptionCaught echoes PCB_STATICINIT=<flag>.
    * V2 = mina-core 2.2.7 -> BLOCKED: readClassDescriptor() applies acceptMatchers BEFORE Class.forName,
            so the non-allowlisted PcbCanary is rejected before initialization -> its static initializer
            never runs -> Beacon empty -> no flag.

BENIGN: PcbCanary's static initializer only reads the per-run ${PCB_FLAG} canary token; no gadget chain,
no command execution. The `canary` mode / class name lives only here / in the held-out client mode, never
in the GIVEN Server or original_poc. (The static initializer is one-shot per server JVM -- the oracle
probes each residual exactly once per fresh server, which is how MINA loads a class in practice.)
"""
from __future__ import annotations

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["static_initializer_before_allowlist"]


def candidate(vector: str = "static_initializer_before_allowlist"):
    return {
        "id": "cve-2026-42778-" + vector,
        "mode": "canary",
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
