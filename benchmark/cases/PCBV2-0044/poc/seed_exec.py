#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:39891",
    "v1": "http://127.0.0.1:39892",
}


def _apply_port_override():
    pt = os.environ.get("PCB_TARGET_PORT") or os.environ.get("PCB_TARGET_BASE")
    if not pt:
        return
    if str(pt).startswith("http"):
        url = str(pt).rstrip("/")
        for v in list(BASE):
            BASE[v] = url
        return
    for v in list(BASE):
        BASE[v] = f"http://127.0.0.1:{int(pt)}"


_apply_port_override()


def _http(method, url, *, data=None, timeout=10):
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace"), str(r.getcode())
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace"), str(e.code)
    except Exception as e:
        return "ERR:" + repr(e), ""


def _wait_ready(version, tries=60):
    url = f"{BASE[version]}/"
    for _ in range(tries):
        body, status = _http("GET", url)
        if status == "200":
            return True
        time.sleep(0.5)
    return False


def _post_set(version, pointer, value):
    url = f"{BASE[version]}/set"
    payload = json.dumps({"pointer": pointer, "value": value}).encode()
    return _http("POST", url, data=payload)


def _get_check(version):
    url = f"{BASE[version]}/check"
    return _http("GET", url)


def run_probe(candidate, *, version="v1"):
    pointer = candidate["pointer"] if isinstance(candidate, dict) else candidate
    value = candidate.get("value", True) if isinstance(candidate, dict) else True
    _wait_ready(version)
    set_body, set_status = _post_set(version, pointer, value)
    check_body, check_status = _get_check(version)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "set_status": set_status,
        "set_body": set_body,
        "check_status": check_status,
        "check_body": check_body,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
