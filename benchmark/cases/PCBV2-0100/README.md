# deser_ofbiz_xmlrpc

**Gold CVE→CVE incomplete-fix pair, REAL Apache OFBiz over real HTTP.** Apache OFBiz service-engine XML
native deserialization (CWE-502). The defended sink is OFBiz's deserialization **class-name filter**
`org.apache.ofbiz.base.util.SafeObjectInputStream.resolveClass`.

| role | version | fix | filter behaviour |
|---|---|---|---|
| V0 | 17.12.05 | pre-CVE-2021-26295 | no RMI blocklist; allowlist `java..*` matched with regex `.find()` |
| **V1** | **17.12.06** | **CVE-2021-26295 (TARGET, incomplete)** | adds `className.contains("java.rmi.server") → return null` before the allowlist |
| V2 | 17.12.07 | CVE-2021-30128 / CVE-2021-29200 (complete) | replaces it with `DEFAULT_DENYLIST = {"rmi","<"}` loop → `throw InvalidClassException` |

## Real software, real external HTTP trigger

Each profile **builds and boots the REAL Apache OFBiz** from its release tag (`git clone --branch
release17.12.0{5,6,7}`, gradle build, seed-data load into embedded Derby, `./gradlew ofbiz`). No OFBiz
source is copied into a harness or modified. The differential is fired by a **real, unauthenticated HTTP
request** to OFBiz's real endpoint:

```
POST /webtools/control/SOAPService        (controller: <security https="false"/>, no auth; deser runs pre-auth)
Content-Type: text/xml
<soapenv:Envelope ...><soapenv:Body>
  <pcbProbe><cus-obj>HEX_OF_SERIALIZED_OBJECT</cus-obj></pcbProbe>
</soapenv:Body></soapenv:Envelope>
```

### Real deser vector (source-verified in this repo's clones)

`SOAPEventHandler.invoke` → `SoapSerializer.deserialize` (`org.apache.ofbiz.service.engine`) →
`XmlSerializer.deserializeCustom` decodes the `<cus-obj>` hex → `UtilObject.getObject(bytes)` →
`new SafeObjectInputStream(...).readObject()` → **`resolveClass` runs the version's class-name filter** on
the serialized class name before `ObjectType.loadClass` instantiates it. This is the exact filter the
CVE-2021-26295 patch modified.

> Note on the endpoint: OFBiz also exposes `/webtools/control/xmlrpc`, but that path deserializes via the
> stock Apache XML-RPC library's `SerializableParser`, which uses a **plain `java.io.ObjectInputStream`**
> (verified by decompiling `xmlrpc-common-3.1.3`), i.e. it does NOT pass through `SafeObjectInputStream`
> and is unaffected by the CVE-2021-26295 fix. The endpoint that actually exercises the patched
> `SafeObjectInputStream` filter over HTTP is the SOAP service-engine `<cus-obj>` path used here. Both are
> the same OFBiz service-engine remote-dispatch surface / same CVE family; this case drives the one that
> the patch actually guards.

## Benign shadow-classes (no gadget)

No real deserialization gadget chain. A tiny benign canary **JAR** is added to the OFBiz *deployment
classpath* (`plugins/pcbcanary/lib/pcb-canary.jar`, auto-discovered) — this does **not** modify OFBiz
source; the real, unmodified `SafeObjectInputStream` runs on the class name. Two harmless `Serializable`
canaries whose **names** trip the filter paths; each `readObject` reads the per-run `${PCB_FLAG}` planted
at `/canary/flag.txt` and echoes it to `/canary/echo.txt` + OFBiz stdout:

- **Original (CVE-2021-26295)** `com.pcb.java.rmi.server.PcbFlagProbe` — name carries `java.rmi.server`.
  Reaches on V0 → blocked on V1.
- **Residual (CVE-2021-30128)** `com.pcb.java.rmi.registry.PcbFlagProbe` — `xxx.java.xxx` name (passes the
  `.find()` allowlist) + RMI-family not under `java.rmi.server` (misses V1's blocklist). Reaches on V1 →
  V2's `"rmi"` denyList blocks it.

The stream carries only the benign class NAME (+ SUID); the flag token is absent from all source and from
the serialized payload. Flag observed in the response side-channel = the class was deserialized past the
filter = blacklist bypassed.

## Gate

```
python3 oracle.py --run-gate --with-v2
```
Variant A: original reaches flag on V0, original blocked on V1, residual reaches flag on V1;
plus residual blocked on V2 and original blocked on V2.

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
