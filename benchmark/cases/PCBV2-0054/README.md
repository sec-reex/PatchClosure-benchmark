# apache-dubbo-serializer-switch-cve-2021-25641

Apache Dubbo — CVE-2020-1948 -> CVE-2021-25641 (client-selected serializer routes around the hessian2
type-allowlist, CWE-502).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL TCP (real-server-tcp, not HTTP —
Dubbo is a network RPC framework).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Each version service runs a REAL, UNMODIFIED `org.apache.dubbo:dubbo` provider (Maven deps from
Central, `app/Provider.java` exporting `DemoService` on `dubbo://0.0.0.0:20880`, no ZooKeeper); the
attacker is a SEPARATE `client` container running the real Dubbo consumer (`app/Client.java`) that
connects over the real docker network to `dubbo://<v0|v1|v2>:20880` and SELECTS the serializer via the
`serialization=` URL param (the frame's serialization-id byte) — not `docker compose exec`. The
provider's own unmodified decode path (`DubboCodec.decodeBody` -> `DecodeableRpcInvocation.decode` ->
hessian RPC-argument deserialization) is the sink. Canary = rce-oob read: `${PCB_FLAG}` is written to
`/canary/flag.txt` (outside the app dir) at provider start; the benign shadow bean
`com.pcb.PcbFlagProbe` (not `java.*`), if instantiated during RPC-argument deserialization, reads it
in its no-arg constructor / `readResolve` and echoes `PCB_PROVIDER_FLAG=<token>` to the PROVIDER log.
No gadget chain, no JNDI, no command execution — the frame carries only a benign class name.

- **V0 = dubbo 2.7.6** (`:20886`, shades hessian-lite 3.2.6 — NO `ClassFactory`; no guards, `DUBBO_PROPS` empty)
  -> the seed's hessian2 argument instantiates `com.pcb.PcbFlagProbe` -> flag echoed.
- **V1 = dubbo 2.7.8** (`:20888`, target; CVE-2020-1948 fix enabled: `-Ddubbo.application.hessian2.whitelist=true`,
  hessian-lite 3.2.8 `ClassFactory` allowlist — only `java.*` allowed, else the class is replaced with
  `HashMap` before construction) -> the hessian2 (serialization-id 2) seed is BLOCKED
  (`client_result ok:java.util.HashMap`, no flag). But the allowlist is hessian2-specific: native-hessian
  (id 10, `dubbo-serialization-native-hession`) uses `com.caucho.hessian.io.Hessian2Input` with its own
  `Hessian2SerializerFactory` that has NO `ClassFactory`, and 2.7.8's `CodecSupport.getSerialization`
  only cross-checks the network id against config for the three JDK ids (3/7/4) — there is no
  `checkSerialization` on 2.7.8 -> the id-10 switch is accepted and the SAME probe class is
  instantiated. Incomplete fix (GHSL-2021-034_043: "native-hessian is similar to hessian2 but does not
  support allowlists ... attackers would still be able to change the protocol to native-hessian and
  evade it").
- **V2 = dubbo 2.7.12** (`:20892`, -25641 fix; whitelist KEPT plus `-Dserialization.security.check=true`)
  -> `CodecSupport.checkSerialization(path, version, id)` throws "Unexpected serialization id:10
  received from network" (at `CodecSupport.checkSerialization:176` -> `DecodeableRpcInvocation.decode:127`)
  BEFORE args are deserialized -> residual BLOCKED; the hessian2 original stays blocked by the whitelist.

- **Original trigger**: `DemoService.probe(new PcbFlagProbe())` over hessian2 (serialization-id 2) —
  on V1 `ClassFactory.load("com.pcb.PcbFlagProbe")` fails the `java\..+` allow pattern and the arg
  deserializes as `HashMap`, never constructed.
- **Residual trigger**: the SAME probe over native-hessian (serialization-id 10) — one byte moves in
  the frame preamble; the class is resolved and instantiated with no allowlist consulted.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.
