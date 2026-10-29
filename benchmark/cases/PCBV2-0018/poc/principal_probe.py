#!/usr/bin/env python3
"""ROUND6 6a principal/state probe for gitea: install+setup, then issue candidate path
requests with the SEED's public-only token (state = token scope; surface = API paths)."""
import sys, json, os, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gitea_util as g

def run(cand, version="v1"):
    if not g.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    flag = os.environ.get("PCB_FLAG") or "pcbflag"
    org, tok = g.setup(version, flag)
    path = cand.get("path", "/api/v1/user/orgs")
    method = cand.get("method", "GET").upper()
    headers = {"Authorization": f"token {tok}"}
    try:
        if method == "POST":
            r = requests.post(g.BASE[version] + path, headers=headers,
                              json=cand.get("params") or {}, timeout=30)
        else:
            r = requests.get(g.BASE[version] + path, headers=headers, timeout=30)
        body = r.text[:400]
        return {"ok": False, "status": r.status_code, "body": body, "path": path}
    except Exception as e:
        return {"ok": False, "status": 0, "body": f"ERR {type(e).__name__}: {e}", "path": path}

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
    print(json.dumps(run(cand, sys.argv[2] if len(sys.argv) > 2 else "v1"), ensure_ascii=False))
