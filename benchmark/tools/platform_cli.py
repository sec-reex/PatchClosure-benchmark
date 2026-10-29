#!/usr/bin/env python3
"""platform_cli: minimal API client for the benchmark platform controller.

Usage:
  platform_cli.py cases [--limit N] [--cursor C]
  platform_cli.py case <case_id>
  platform_cli.py start <case_id> [--profile agent_v1_patch|method_v0v1|maintainer]
                              [--ttl N] [--key IDEM_KEY] [--wait N]
  platform_cli.py status <run_id>
  platform_cli.py submit-flag <run_id> <flag> [--key K]
  platform_cli.py submit-cand <run_id> <candidate.json> [--adapter http_request] [--key K]
  platform_cli.py stop <run_id> [--reason R]

Exit code is 0 only on success; failures print to stderr and exit non-zero.
"""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8787/api/v1"


def _req(method, path, body=None, key=None, timeout=300):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if key:
        h["Idempotency-Key"] = key
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode())
        except Exception:
            detail = {}
        return e.code, detail


def cmd_cases(args):
    path = f"/cases?limit={args.limit}&cursor={args.cursor}&certification={args.cert}"
    st, d = _req("GET", path)
    print(json.dumps(d, ensure_ascii=False, indent=1))
    return 0 if st == 200 else 1


def cmd_case(args):
    st, d = _req("GET", f"/cases/{args.case_id}")
    print(json.dumps(d, ensure_ascii=False, indent=1))
    return 0 if st == 200 else 1


def cmd_start(args):
    body = {"case_id": args.case_id, "exposure_profile": args.profile,
            "ttl_seconds": args.ttl, "wait_ready_seconds": args.wait}
    st, d = _req("POST", "/runs", body=body, key=args.key, timeout=600)
    print(json.dumps(d, ensure_ascii=False, indent=1))
    if st not in (200, 201, 202):
        return 1
    if args.wait == 0:
        return 0
    # poll until ready / error / expiry
    run_id = d.get("run_id")
    for _ in range(int(args.wait) // 5 + 1):
        st2, d2 = _req("GET", f"/runs/{run_id}")
        stt = d2.get("state")
        if stt in ("ready", "error", "expired", "stopped"):
            print(json.dumps(d2, ensure_ascii=False, indent=1))
            return 0 if stt == "ready" else 1
        time.sleep(5)
    return 0


def cmd_status(args):
    st, d = _req("GET", f"/runs/{args.run_id}")
    print(json.dumps(d, ensure_ascii=False, indent=1))
    return 0 if st == 200 else 1


def cmd_submit_flag(args):
    st, d = _req("POST", f"/runs/{args.run_id}/submissions",
                 body={"type": "flag", "value": args.flag}, key=args.key)
    print(json.dumps(d, ensure_ascii=False, indent=1))
    ok = d.get("accepted") if isinstance(d, dict) else False
    return 0 if (st == 200 and ok) else 1


def cmd_submit_cand(args):
    cand = json.load(open(args.candidate_file))
    st, d = _req("POST", f"/runs/{args.run_id}/submissions",
                 body={"type": "candidate", "adapter": args.adapter, "candidate": cand},
                 key=args.key)
    print(json.dumps(d, ensure_ascii=False, indent=1))
    ok = d.get("accepted") if isinstance(d, dict) else False
    return 0 if (st == 200 and ok) else 1


def cmd_stop(args):
    st, d = _req("POST", f"/runs/{args.run_id}/stop",
                 body={"reason": args.reason}, key=args.key)
    print(json.dumps(d, ensure_ascii=False, indent=1))
    return 0 if st == 200 else 1


def main():
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("cases")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--cursor", default="")
    p.add_argument("--cert", default="all")
    p.set_defaults(fn=cmd_cases)

    p = sub.add_parser("case")
    p.add_argument("case_id")
    p.set_defaults(fn=cmd_case)

    p = sub.add_parser("start")
    p.add_argument("case_id")
    p.add_argument("--profile", default="method_v0v1")
    p.add_argument("--ttl", type=int, default=7200)
    p.add_argument("--wait", type=int, default=120)
    p.add_argument("--key", default="")
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("status")
    p.add_argument("run_id")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("submit-flag")
    p.add_argument("run_id")
    p.add_argument("flag")
    p.add_argument("--key", default="")
    p.set_defaults(fn=cmd_submit_flag)

    p = sub.add_parser("submit-cand")
    p.add_argument("run_id")
    p.add_argument("candidate_file")
    p.add_argument("--adapter", default="http_request")
    p.add_argument("--key", default="")
    p.set_defaults(fn=cmd_submit_cand)

    p = sub.add_parser("stop")
    p.add_argument("run_id")
    p.add_argument("--reason", default="completed")
    p.add_argument("--key", default="")
    p.set_defaults(fn=cmd_stop)

    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
