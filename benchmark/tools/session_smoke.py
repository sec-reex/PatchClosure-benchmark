#!/usr/bin/env python3
"""Smoke-test the agent session API against a live controller (run on gpu1)."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("PCB_API", "http://127.0.0.1:8787")


def req(method: str, path: str, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    r = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return e.code, parsed


def fail(msg, extra=None):
    print("FAIL:", msg, file=sys.stderr)
    if extra is not None:
        print(json.dumps(extra, ensure_ascii=False, indent=2)[:4000], file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print("OK:", msg, flush=True)


def poll_session(sid: str, timeout_s: int):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        code, body = req("GET", f"/api/v1/sessions/{sid}")
        if code != 200:
            fail(f"GET session HTTP {code}", body)
        snap = (
            body.get("state"),
            (body.get("v0") or {}).get("state"),
            (body.get("v1") or {}).get("state"),
        )
        if snap != last:
            last = snap
            print(f"  state={snap[0]} v0={snap[1]} v1={snap[2]}", flush=True)
        if body.get("state") in ("ready", "error"):
            return body
        time.sleep(5)
    fail("session poll timeout", last)


def ls_brief(p: str):
    path = Path(p)
    if not path.exists():
        return f"MISSING {p}"
    names = sorted(x.name for x in path.iterdir())
    return f"{p} -> {names}"


def smoke_case(case_id: str, timeout_s: int) -> dict:
    print(f"\n===== {case_id} =====", flush=True)
    code, created = req("POST", "/api/v1/sessions", {"case_id": case_id})
    if code not in (200, 201, 202):
        fail(f"POST session HTTP {code}", created)
    sid = created.get("session_id")
    if not sid:
        fail("no session_id", created)
    ok(f"created {sid} state={created.get('state')}")

    body = poll_session(sid, timeout_s)
    if body.get("state") != "ready":
        fail("session did not become ready", body)
    ok("session ready")

    tmp = body.get("tmp") or body.get("workspace")
    paths = body.get("paths") or {}
    if not tmp:
        fail("no tmp/workspace in ready response", body)
    ok(f"tmp={tmp}")
    print("  ", ls_brief(tmp), flush=True)

    checks = {}
    for name in ("v0", "v1", "patch_real.diff", "exp"):
        p = Path(tmp) / name
        checks[name] = p.exists()
        if not p.exists():
            fail(f"workspace missing {name}", {"tmp": tmp, "paths": paths, "ls": ls_brief(tmp)})
    exp_files = sorted(x.name for x in (Path(tmp) / "exp").iterdir()) if checks["exp"] else []
    if not exp_files:
        fail("exp/ is empty", paths)
    ok(f"workspace has v0/ v1/ patch_real.diff exp/{exp_files}")

    v0e = (body.get("v0") or {}).get("endpoints") or []
    v1e = (body.get("v1") or {}).get("endpoints") or []
    if not v0e or not v1e:
        fail("missing endpoints", {"v0": body.get("v0"), "v1": body.get("v1")})
    for label, eps in (("v0", v0e), ("v1", v1e)):
        ep = eps[0]
        if not ep.get("port"):
            fail(f"{label} endpoint has no port", ep)
        if not ep.get("host"):
            fail(f"{label} endpoint has no host", ep)
    ok(f"v0 {v0e[0].get('url') or v0e[0]}  v1 {v1e[0].get('url') or v1e[0]}")

    v0_id = (body.get("v0") or {}).get("run_id")
    v1_id = (body.get("v1") or {}).get("run_id")

    code, cinfo = req("GET", f"/api/v1/cases/{case_id}")
    if code != 200:
        fail(f"GET case HTTP {code}", cinfo)
    if not cinfo.get("recent_runs"):
        fail("GET case has no recent_runs", cinfo)
    ok(f"GET case recent_runs={len(cinfo['recent_runs'])}")

    code, v0s = req("POST", f"/api/v1/runs/{v0_id}/submissions",
                    {"type": "verify", "mode": "seed"}, timeout=180)
    if code != 200:
        fail(f"v0 verify HTTP {code}", v0s)
    if v0s.get("rc") != 0:
        fail("v0 seed should be rc=0 (effect + flag)", v0s)
    ok(f"v0 seed verify rc={v0s.get('rc')} outcome={v0s.get('outcome')}")

    code, v1s = req("POST", f"/api/v1/runs/{v1_id}/submissions",
                    {"type": "verify", "mode": "seed"}, timeout=180)
    if code != 200:
        fail(f"v1 verify HTTP {code}", v1s)
    if v1s.get("rc") != 10:
        fail("v1 seed should be rc=10 (blocked)", v1s)
    ok(f"v1 seed verify rc={v1s.get('rc')} outcome={v1s.get('outcome')}")

    code, run0 = req("GET", f"/api/v1/runs/{v0_id}")
    flag = (run0 or {}).get("flag") or ""
    if not flag.startswith("PCBFLAG_"):
        fail("operator GET run did not include flag (needed for hmac test)", run0)
    if "flag" in (body.get("v0") or {}):
        fail("session GET leaked flag on v0", body.get("v0"))

    code, good = req("POST", f"/api/v1/sessions/{sid}/flag", {"value": flag})
    if code != 200 or not good.get("accepted") or "v0" not in (good.get("matched") or []):
        fail("correct flag not accepted against v0", good)
    ok(f"flag hmac accepted matched={good.get('matched')}")

    code, bad = req("POST", f"/api/v1/sessions/{sid}/flag",
                    {"value": "PCBFLAG_dead_00000000000000000000000000000000"})
    if code != 200 or bad.get("accepted"):
        fail("wrong flag was accepted", bad)
    ok("wrong flag rejected")

    code, flg = req("POST", f"/api/v1/runs/{v0_id}/submissions",
                    {"type": "flag", "value": flag})
    if code != 200 or not flg.get("accepted"):
        fail("run-level type=flag rejected a good flag", flg)
    ok("run-level type=flag accepted")

    code, stopped = req("POST", f"/api/v1/sessions/{sid}/stop")
    if code != 200:
        fail(f"stop HTTP {code}", stopped)
    ok(f"stopped {sid}")

    leftover = Path(tmp)
    if leftover.exists() and leftover.is_dir() and not leftover.is_symlink():
        # stop unlinks /tmp/pcb_* symlink; work/sessions/<id> is rmtree'd
        pass
    if leftover.is_symlink() or leftover.exists():
        print(f"WARN: tmp path still exists after stop: {tmp}", flush=True)

    code, gone = req("GET", f"/api/v1/sessions/{sid}")
    if code != 404:
        print(f"WARN: GET session after stop HTTP {code} (expected 404)", gone, flush=True)
    else:
        ok("GET session after stop is 404")

    return {
        "case_id": case_id, "session_id": sid, "tmp": tmp,
        "v0_url": v0e[0].get("url"), "v1_url": v1e[0].get("url"),
        "v0_seed_rc": v0s.get("rc"), "v1_seed_rc": v1s.get("rc"),
        "exp_files": exp_files,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cases", nargs="+")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    code, hz = req("GET", "/healthz")
    if code != 200:
        fail("healthz", hz)
    print("healthz", hz, flush=True)
    if "agent" not in str(hz.get("platform", "")):
        fail("controller is not r24-v2-agent; restart uvicorn after syncing controller/", hz)

    code, bad = req("POST", "/api/v1/sessions", {"case_id": "PCBV2-NOPE"})
    if code not in (404, 422, 500):
        fail("bogus case_id should error", {"http": code, "body": bad})
    ok(f"bogus case_id HTTP {code} body={bad}")

    results = []
    for cid in args.cases:
        results.append(smoke_case(cid, args.timeout))

    print("\n===== SUMMARY =====")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
