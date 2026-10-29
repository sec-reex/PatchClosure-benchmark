#!/usr/bin/env python3
"""Shared EXTERNAL-HTTP orchestration for fastxmlparser_entityname_regex_injection.

One "probe" = a single external HTTP POST of an XML document to the version's real Express
service `POST /parse`, which runs the REAL, unmodified
`new XMLParser({processEntities:true}).parse(req.body)` over the raw request body. The observable
result is the JSON HTTP response; the per-run ${PCB_FLAG} (carried as the attacker's DOCTYPE
entity value) appears in `parsed` IFF the DOCTYPE entity-name regex injection shadowed the
built-in &lt; reference during the parse. Nothing in fast-xml-parser is modified -- the version
installed per env (v0/v1/v2) is the only guard.
"""
import json
import urllib.request

# Host-published ports (oracle / PoCs run on the host and reach the service EXTERNALLY).
HOST_APP = {
    "v0": "http://127.0.0.1:34910",
    "v1": "http://127.0.0.1:34911",
    "v2": "http://127.0.0.1:34912",
}


def post_parse(payload: str, version: str, timeout: int = 30) -> dict:
    """External HTTP POST of a raw XML document (Content-Type text/xml) to `version`'s /parse.
    Returns the parsed JSON response ({fxp, loaded, error, parsed})."""
    url = HOST_APP[version] + "/parse"
    req = urllib.request.Request(
        url, data=payload.encode("utf-8"),
        headers={"Content-Type": "text/xml"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except Exception:
        return {"_raw": body}


def health(version: str, timeout: int = 3) -> bool:
    try:
        with urllib.request.urlopen(HOST_APP[version] + "/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False
