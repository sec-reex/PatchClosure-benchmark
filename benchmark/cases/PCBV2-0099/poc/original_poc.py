#!/usr/bin/env python3
"""[GIVEN] CVE-2024-52046 seed exploit for deser_mina_objser (REAL MINA TCP server).

The classic MINA deserialization vector: an external TCP client sends an attacker-chosen Serializable
class to the REAL running MINA server (NioSocketAcceptor + ObjectSerializationCodecFactory) as a NORMAL
MINA type-1 payload. The seed class is `PcbSeed`, whose flag read happens during full reconstruction,
in its readObject().

    mode=type1   (Client sends PcbSeed as a normal MINA type-1 wire descriptor over TCP)

On V0 (mina-core 2.2.3) there is NO class allowlist API, so getObject() reconstructs PcbSeed and its
readObject() reads the planted /canary/flag.txt; the server echoes the flag back over TCP (REACHES).
On V1 (2.2.6, CVE-2024-52046 patched) the acceptMatchers allowlist -- configured on the server to accept
only the legit class `PcbExpected` -- rejects the type-1 PcbSeed inside resolveClass()'s non-null branch
and throws ClassNotFoundException BEFORE construction, so readObject() never runs and no flag is echoed
(BLOCKED). The block on V1 is specifically the class-filter guard the CVE-2024-52046 fix added.
"""


def candidate():
    return {
        "id": "cve-2024-52046-type1-unbounded-deser-seed",
        "mode": "type1",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
