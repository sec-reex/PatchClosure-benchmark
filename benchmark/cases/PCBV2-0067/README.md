# deser_jenkins_remoting

Jenkins remoting — CVE-2015-8103 → CVE-2017-1000353 (Java deserialization deny-list that only inspects
the OUTER stream, bypassed via a `java.security.SignedObject` nested unfiltered stream, CWE-502).
**Genuine incomplete fix; gate passed on real Docker over a REAL EXTERNAL TCP trigger
(`python3 oracle.py --run-gate --with-v2` — see `repro.log`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

hudson.remoting is a NETWORK channel framework, not an HTTP app. Each profile maven-pulls the REAL
published `org.jenkins-ci.main:remoting` jar at the pinned version (repo.jenkins-ci.org; no remoting
code edited) and runs a REAL remoting TCP server (`app/Server.java`, `ServerSocket` on :9009) that
reads each incoming object off the socket through the REAL, unmodified
`hudson.remoting.ObjectInputStreamEx(in, cl)` + `ClassFilter.DEFAULT` sink (the CLI `Command#readFrom`
form); for a `SignedObject` the server calls `getObject()`. A SEPARATE external `client` container
(`app/Client.java`) connects over real TCP across the docker network by service name and writes the
serialization stream (`docker compose run --rm --no-deps client sh -c "java -cp $(cat /work/cp.txt)
Client <v0|v1|v2> 9009 <mode>"`). Benign rce-oob canary: `${PCB_FLAG}` is planted at server start in
`/canary/flag.txt` OUTSIDE the app dir; `PcbSeed.readObject()` (a benign shadow class parked in the
blacklisted `org.apache.commons.collections.functors` package) reads it ONLY during full
reconstruction and the server echoes it back over the same TCP connection. The flag never travels on
the wire — the client serializes only a bare PcbSeed; no gadget chain, no command execution.

- **V0 = remoting 2.52** (`:19252`) — pre-CVE-2015-8103: `ClassFilter` ABSENT,
  `ObjectInputStreamEx.resolveClass()` = bare `Class.forName(name, false, cl)` → direct PcbSeed
  reconstructs, `readObject()` reads the canary → echoed. Everything open.
- **V1 = remoting 2.53** (`:19253`, target; CVE-2015-8103 / [SECURITY-218] commit `7c35ed9a`) —
  `resolveClass()` now runs `ClassFilter.DEFAULT.check(name)`: the blacklist
  (`org.codehaus.groovy.runtime.*`, `org.apache.commons.collections.functors.*`, `*org.apache.xalan*`)
  rejects the direct PcbSeed with `SecurityException:Rejected: ...` BEFORE construction → seed
  BLOCKED (`PcbExpected` control still passes — selective, not deny-all). But `java.security.SignedObject`
  is NOT on that blacklist → a SignedObject-wrapped PcbSeed passes the outer filter and
  `SignedObject.getObject()`'s NEW, PLAIN `ObjectInputStream` reconstructs it → residual REACHES.
  Incomplete fix.
- **V2 = remoting 3.16** (`:19316`, CVE-2017-1000353 fix state) — first remoting release whose OWN
  `ClassFilter.DEFAULT` adds `^java[.]security[.]SignedObject$` (the SECURITY-429 fix of 2017-04-26,
  Jenkins 2.57 / LTS 2.46.2, added it core-side; JEP-200 consolidation) → the outer filter rejects the
  SignedObject before `getObject()` → residual BLOCKED (direct PcbSeed stays blocked too).

- **Original trigger**: `mode=direct` — a plain-serialized
  `org.apache.commons.collections.functors.PcbSeed` sent straight to the TCP deser sink; on V1 the
  blacklisted name is rejected in the OUTER stream's `resolveClass`.
- **Residual trigger**: `mode=signed` — the SAME PcbSeed wrapped in a `java.security.SignedObject`
  (throwaway client-side RSA keypair; `getObject()` does not verify the signature): the outer stream
  only names `java.security.SignedObject` (not blacklisted at 2.53), and the nested, unfiltered
  `ObjectInputStream` inside `getObject()` reconstructs PcbSeed past the deny-list. Only the WIRE
  STRUCTURE differs from the seed.

> NOTE: `patch_real.diff`'s header labels commit `6000a6f0` as the "CVE-2015-8103 fix", but the diff
> itself shows `ClassFilter.java` ALREADY existing with the three-entry blacklist (it refactors
> `DEFAULT` into a lazy `getDefaultFilter()`/`RegExpClassFilter` + file override, still with NO
> SignedObject entry). `patch.diff` and `case.json` attribute the introduction of the filter to commit
> `7c35ed9a` ([SECURITY-218]) — `6000a6f0` is a later in-place refactor, not the introducing commit.

> NOTE: `_heldout/bypass_poc.py` is claimed as held out in `case.json` (`held_out`), but an identical
> copy exists at `poc/bypass_poc.py` (`diff` reports the two files SAME).

> NOTE: `case.json` `provenance.notes` (and `repro.log`) say stale leftover files of the old in-process
> build (`src/Driver.java`, `src/Serializer.java`, `src/PcbExpected.java`, `src/org/apache/commons/
> collections/functors/PcbSeed.java`) are "left for batch cleanup" — but no `src/` tree exists in the
> case directory anymore (`ls` confirms; only `app/` remains). The cleanup already happened; the
> case.json/repro.log text is stale. `provenance.notes` also points to
> `cve_pair.note_on_v2_version_choice`, a key that does not exist in `case.json`'s `cve_pair` object.

Run: `python3 oracle.py --run-gate --with-v2` (needs `PCB_FLAG`). See `repro.log` and `case.json`.
