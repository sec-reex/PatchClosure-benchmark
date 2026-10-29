# apache-mina-cve-2026-42778

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Apache MINA — **CVE-2024-52046 → CVE-2026-42778** (Deserialization of untrusted data, CWE-502).
PatchClosure-Bench differential case, **Variant A** (same sink, same canary file). Status: **gate_passed**.
Run mode: **real-server-tcp** — MINA is a network framework, so each version runs a REAL MINA
`NioSocketAcceptor` TCP server (`app/Server.java`) and a SEPARATE `client` container (`app/Client.java`)
triggers it over TCP across the docker network (genuine external network trigger, not an in-process harness).

## The incomplete fix
- **Sink:** `org.apache.mina.core.buffer.AbstractIoBuffer.getObject(ClassLoader)` (the
  `ObjectSerializationDecoder` deserialization path). Its inner `ObjectInputStream` overrides
  `readClassDescriptor()` (type-1 Serializable → `Class.forName(name, true, cl)`) and `resolveClass()`.
- **CVE-2024-52046** (V0→V1, mina-core **2.2.3 → 2.2.4**): pre-fix there is **no allowlist** — any
  class is deserialized (CVSS 10.0 RCE). The fix ADDS an `acceptMatchers`/`ClassNameMatcher` allowlist
  (`accept(Class...)`/`accept(Pattern)`/`accept(String...)`, default-deny) enforced in `resolveClass()`.
- **CVE-2026-42778** (V1→V2, mina-core **2.2.4 → 2.2.7**): the allowlist was applied **too late**.
  `readClassDescriptor()` calls `Class.forName(className, /*initialize=*/true, cl)` **before** the
  allowlist is consulted, so a non-allowlisted class's **static initializer runs before it is
  rejected**. The 2.2.7 fix moves the allowlist check **before** `Class.forName`.

## Roles
| ver | mina-core | state |
|-----|-----------|-------|
| V0  | 2.2.3 | pre-CVE-2024-52046: no allowlist → any class deserialized |
| V1  | 2.2.4 | CVE-2024-52046 patched (allowlist present) **but** CVE-2026-42778 residual open — **target** |
| V2  | 2.2.7 | CVE-2026-42778 patched (allowlist moved before `Class.forName`) — negative |

## Benign canary (rce-oob, read) — two distinct side-channels
A random per-run `${PCB_FLAG}` is written to `/canary/flag.txt` (outside the app dir) in the SERVER
container at start. The external client sends a benign class as a normal MINA type-1 stream over TCP;
which side-channel surfaces the flag is what distinguishes the seed from the residual:
- **PcbSeed** (seed, `mode=seed`) reads the flag only in `readObject()` → the server echoes
  `PCB_READOBJECT=<flag>`. The allowlist blocks the deserialization on V1 (rejected before construction),
  so `readObject` never runs and the channel is empty.
- **PcbCanary** (residual, `mode=canary`) reads the flag in a **static initializer** (into the shared
  `Beacon`) when the class is resolved by `Class.forName(name,true)` → the server's `exceptionCaught`
  (the class is then rejected) echoes `PCB_STATICINIT=<flag>`. On V1 this fires **before** the allowlist
  rejects the class = the CVE-2026-42778 residual.

Each class has exactly ONE flag channel, so a single `${PCB_FLAG}` token tells them apart. No gadget
chain, no command execution. The client generates the MINA streams itself with pure `java.io` (no canary
in the client container), so they carry only the class name + descriptor — never the flag (`PcbSeed.flag`
is transient). A static initializer is one-shot per server JVM, so the oracle probes each `(version,class)`
exactly once per fresh server — exactly how MINA loads a class in production.

## Run the gate
```bash
python3 oracle.py --run-gate --with-v2   # builds v0/v1/v2, probes, tears down (down -v --rmi all)
```
Verified: `reach@v0=true`, `blocked@v1=true`, `bypass_reach@v1=true` → **passed**;
`residual_blocked@v2=true`. See `repro.log`.
