#!/usr/bin/env python3
"""[GIVEN] CVE-2024-52046 seed exploit for apache-mina-cve-2026-42778 (REAL MINA TCP server).

The classic MINA deserialization vector: an external TCP client sends an attacker-chosen Serializable
class to the REAL running MINA server (NioSocketAcceptor + ObjectSerializationCodecFactory) as a NORMAL
MINA type-1 payload. The seed class is `PcbSeed`, whose flag read happens ONLY during full
reconstruction, in its readObject() (it has NO flag-reading static initializer).

    mode=seed   (Client sends PcbSeed as a normal MINA type-1 wire descriptor over TCP)

On V0 (mina-core 2.2.3) there is NO class allowlist, so getObject() reconstructs PcbSeed and its
readObject() reads the planted /canary/flag.txt; the server echoes PCB_READOBJECT=<flag> back over TCP
(REACHES). On V1 (2.2.4, CVE-2024-52046 patched) the acceptMatchers allowlist -- configured on the server
to accept only the legit class `PcbExpected` -- rejects PcbSeed inside resolveClass() and throws
ClassNotFoundException BEFORE construction, so readObject() never runs and no readObject flag is echoed
(BLOCKED). The block on V1 is specifically the class-filter guard the CVE-2024-52046 fix added.
"""


def candidate():
    return {
        "id": "cve-2024-52046-readobject-unbounded-deser-seed",
        "mode": "seed",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
