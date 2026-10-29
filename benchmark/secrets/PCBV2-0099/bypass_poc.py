#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-42779 residual for deser_mina_objser (REAL MINA TCP server).

CVE-2024-52046's fix added a class allowlist (acceptMatchers / ClassNameMatcher, default-deny, accept()
API) to the MINA decoder / AbstractIoBuffer.getObject(). But that allowlist was enforced ONLY in
resolveClass()'s NON-NULL (type-1) branch:

    protected Class<?> resolveClass(ObjectStreamClass desc) ... {
        Class<?> clazz = desc.forClass();
        if (clazz == null) {                     // <-- type-0 / null-clazz branch: NO allowlist
            String name = desc.getName();
            return Class.forName(name, false, classLoader);
        } else {                                 // <-- type-1 branch: acceptMatchers enforced
            ... for (matcher : acceptMatchers) if (matcher.matches(className)) return clazz;
            throw new ClassNotFoundException();
        }
    }

MINA's getObject() reads a per-descriptor TYPE byte: readClassDescriptor() routes a 0x00 byte to
super.readClassDescriptor(), which yields a descriptor whose forClass() is null -> resolveClass() takes
the null-clazz branch and does Class.forName(name, false) with NO allowlist. An external TCP client fully
controls the wire bytes, so the residual sends the SAME PcbSeed but with its class descriptor forced to
the type-0 form (0x00 + a standard Java class descriptor) instead of the normal type-1 form. This is the
CVE-2026-41635 / CVE-2026-42779 type-0/null-clazz allowlist-bypass vector.

    mode=type0   (Client sends the SAME PcbSeed forced into a MINA type-0/null-clazz descriptor over TCP)

Source-verified: AbstractIoBuffer.java is BYTE-IDENTICAL between mina-core 2.2.5 and 2.2.6 -- the
CVE-2026-41635 fix was never backported to the 2.2.x line -- so the type-0 branch is still unguarded on
V1 = 2.2.6. CVE-2026-42779 (the incomplete-fix follow-up) closes it in 2.2.7 by hoisting the acceptMatchers
check ahead of every Class.forName in resolveClass() (covering BOTH branches) and readClassDescriptor().

Same real MINA server, same sink (getObject()), same canary class (PcbSeed), same rce-oob channel
(/canary/flag.txt read in readObject, echoed back over TCP) as the seed; ONLY the wire descriptor type
moves from 1 (normal, allowlist-checked) to 0 (null-clazz, allowlist-skipped).

Contract (verified on real Docker via oracle.py, external TCP client -> real MINA server):
    * V1 = mina-core 2.2.6 -> REACHES: resolveClass()'s null-clazz branch loads PcbSeed via
            Class.forName(name, false) with NO allowlist -> reconstructed, readObject echoes the flag.
    * V2 = mina-core 2.2.7 -> BLOCKED: resolveClass() applies acceptMatchers FIRST for the null-clazz
            branch too -> non-allowlisted PcbSeed rejected before Class.forName -> no flag.

BENIGN: PcbSeed.readObject() only echoes the per-run ${PCB_FLAG} canary token; no gadget chain, no
command execution. The type-0 vector name lives only here / in the held-out client mode, never in the
GIVEN Server or original_poc.
"""
from __future__ import annotations

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["type0_null_clazz_descriptor"]


def candidate(vector: str = "type0_null_clazz_descriptor"):
    return {
        "id": "cve-2026-42779-" + vector,
        "mode": "type0",
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
