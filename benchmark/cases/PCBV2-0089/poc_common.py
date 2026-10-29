#!/usr/bin/env python3
"""Shared EXTERNAL-HTTP orchestration for codeinj_pyyaml_fullloader.

One "probe" = a single external HTTP POST of a YAML document to the version's real
Flask service `POST /parse`, which runs the REAL, unmodified `yaml.full_load` over the
raw request body. The observable result is the JSON HTTP response; the per-run
${PCB_FLAG} appears in `leaked` IFF the FullConstructor object escape fired during the
load and its benign reader copied /flag into the leak sink. Nothing in PyYAML is
modified -- the version installed per env (v0/v1/v2) is the only guard.
"""
import json
import urllib.request

# Host-published ports (oracle / PoCs run on the host and reach the service EXTERNALLY).
HOST_APP = {
    "v0": "http://127.0.0.1:34810",
    "v1": "http://127.0.0.1:34811",
    "v2": "http://127.0.0.1:34812",
}


def post_parse(payload: str, version: str, timeout: int = 30) -> dict:
    """External HTTP POST of a raw YAML document to `version`'s /parse. Returns the parsed
    JSON response ({pyyaml, loaded, error, result, leaked})."""
    url = HOST_APP[version] + "/parse"
    req = urllib.request.Request(
        url, data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-yaml"}, method="POST",
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
