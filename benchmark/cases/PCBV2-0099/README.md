# deser_mina_objser

Apache MINA — CVE-2024-52046 -> CVE-2026-42779 (Deserialization class-name allowlist, CWE-502).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL TCP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

A REAL MINA TCP server (`app/Server.java`, `NioSocketAcceptor` +
`ProtocolCodecFilter(ObjectSerializationCodecFactory)`) listens on container port 9009. A SEPARATE
external `client` container (`app/Client.java`) connects over the docker network and writes a crafted
length-prefixed MINA serialized stream; the server's REAL, unmodified published mina-core decoder
(`ObjectSerializationDecoder.doDecode` -> `in.setMatchers(acceptMatchers)` ->
`AbstractIoBuffer#getObject(ClassLoader)`) deserializes it through the version's own allowlist.
Same sink, same CVE-2024-52046 fix mechanism (`acceptMatchers` / `ClassNameMatcher`, default-deny);
CVE-2026-42779 is advisory-declared the incomplete fix of CVE-2026-41635 (never backported to 2.2.x).

- **V0 = mina-core 2.2.3** (`:19030` -> 9009) — NO allowlist API (pre-CVE-2024-52046): `resolveClass`
  returns any class -> the seed is fully reconstructed -> seed reaches the canary.
- **V1 = mina-core 2.2.6** (`:19060` -> 9009, target) — CVE-2024-52046 allowlist present, configured
  (via reflection, so one source compiles on 2.2.3) to accept ONLY `PcbExpected`: the NORMAL type-1
  seed is BLOCKED (`ClassNotFoundException` in `resolveClass`'s non-null branch), but the type-0 /
  null-clazz branch still calls `Class.forName(name, false)` with NO allowlist -> the residual
  REACHES the canary. `AbstractIoBuffer.java` is byte-identical 2.2.5==2.2.6. Incomplete fix.
- **V2 = mina-core 2.2.7** (`:19070` -> 9009, -42779 fix) — `resolveClass` hoists the acceptMatchers
  check ahead of every `Class.forName` (BOTH branches) -> residual BLOCKED
  (`Class not in accept list PcbSeed`).

Benign shadow-class channel: `${PCB_FLAG}` (random per-run token) is written to `/canary/flag.txt`
OUTSIDE the app dir at server-container start; `PcbSeed.readObject()` reads it ONLY during server-side
reconstruction into a transient field (never on the wire), and the server IoHandler echoes it back over
the SAME TCP connection. SUCCESS = token in the external client's received bytes. No gadget chain, no
ProcessBuilder, no command execution.

- **Original benign-shadow trigger**: `PcbSeed` sent as a NORMAL MINA type-1 wire descriptor
  (`write(1)+writeUTF(name)`, client `mode=type1`) — allowlist-checked in `resolveClass`'s non-null
  branch; blocked on 2.2.6.
- **Residual benign-shadow trigger**: the SAME `PcbSeed` with its descriptor forced to the type-0
  form (`0x00` + standard Java class descriptor, client `mode=type0`) — routed to
  `super.readClassDescriptor()` -> `forClass()==null` -> `Class.forName(name,false)` with NO
  allowlist; open on 2.2.6, closed in 2.2.7.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: the case was rebuilt 2026-07-15 from a literal CVE-2026-41635 -> CVE-2026-42779 /
> 2.2.5->2.2.6->2.2.7 three-version framing, which was REFUTED (2.2.5 `AbstractIoBuffer.java` ==
> 2.2.6, so V1==V0 for the sink); it is now CVE-2024-52046 -> CVE-2026-42779 with V0=2.2.3.
> Also, `repro.log`'s teardown section lists stale leftover `src/` files (old in-process build),
> but no `src/` directory exists in the case dir anymore; and the provenance notes cite a
> `cve_pair.note_on_literal_41635_42779_pair` key that is absent from `cve_pair`.
