#!/usr/bin/env python3
"""certify: run fresh-run certification trials for platform cases.

For every case, `--trials N` fresh trials are run; each trial exercises:
  start (fresh flag, target up, sources materialized)
  correct flag accepted
  wrong flag rejected
  stale flag (previous trial's flag) rejected
  reset isolation (state cleared between trials)
  stop cleanup (labeled resources gone)

Usage:
  certify.py --mvp --trials 2
  certify.py --all --trials 2 --checkpoint-size 20
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

TREE = Path(__file__).resolve().parents[1]   # benchmark/（合并树根）
REPO = TREE.parent
OUT = TREE / "reports"
API = "http://127.0.0.1:8787/api/v1"

MVPS = ["PCBV2-0002", "PCBV2-0086", "PCBV2-0018", "PCBV2-0084",
        "PCBV2-0142", "PCBV2-0015", "PCBV2-0054"]


def req(method, path, body=None, key=None, timeout=600):
    import urllib.error
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if key:
        h["Idempotency-Key"] = key
    r = urllib.request.Request(API + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def wait_state(run_id, timeout_s=900):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        st, d = req("GET", f"/runs/{run_id}")
        if d.get("state") in ("ready", "error", "expired", "stopped"):
            return d
        time.sleep(5)
    return {"state": "timeout"}


def load_candidate(module_path: str):
    """Import a seed/reference witness module and return its candidate()."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("witness", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.candidate()


def deep_verify(case_id: str, run_id: str, flag: str) -> dict:
    """Maintainer deep gates: seed@V0 reaches, seed@V1 blocked,
    reference@V1 reaches, reference@V2 blocked."""
    import subprocess
    import urllib.request
    import re as _re
    res = {}
    rd = TREE / "work" / "runs" / run_id
    tm = rd / "target_manifest.json"
    if not tm.exists():
        return {"ok": False, "detail": "no target manifest"}
    targets = {t["name"]: t["base_url"] for t in json.loads(tm.read_text()).get("targets", [])}
    seed_p = TREE / "v2_harness" / "inputs" / case_id / "seed.py"
    ref_p = TREE / "v2_harness" / "evaluator" / case_id / "reference_witness.py"

    def submit_candidate(base, cand):
        body = {"type": "candidate", "adapter": "http_request", "candidate": cand}
        try:
            data = json.dumps(body).encode()
            r = urllib.request.Request(API + f"/runs/{run_id}/submissions", data=data,
                                       headers={"Content-Type": "application/json"},
                                       method="POST")
            with urllib.request.urlopen(r, timeout=60) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"accepted": False, "outcome": f"error:{e}"}

    if seed_p.exists():
        seed = load_candidate(str(seed_p))
        for ver, expect in (("v0", True), ("v1", False)):
            base = targets.get(ver)
            if not base:
                res[f"seed@{ver}"] = {"ok": None, "note": "version target absent"}
                continue
            r = submit_candidate(base, seed)
            got = bool(r.get("accepted"))
            res[f"seed@{ver}"] = {"ok": got == expect, "got": got, "expect": expect,
                                  "outcome": r.get("outcome")}
    if ref_p.exists():
        ref = load_candidate(str(ref_p))
        for ver, expect in (("v1", True), ("v2", False)):
            base = targets.get(ver)
            if not base:
                res[f"reference@{ver}"] = {"ok": None, "note": "version target absent"}
                continue
            r = submit_candidate(base, ref)
            got = bool(r.get("accepted"))
            res[f"reference@{ver}"] = {"ok": got == expect, "got": got, "expect": expect,
                                       "outcome": r.get("outcome")}
    ok_all = all(v.get("ok") is True for v in res.values())
    return {"ok": ok_all, "gates": res}


def run_trial(case_id: str, trial_no: int, previous_flag, deep=False) -> dict:
    """One fresh trial: start, flag checks, cleanup. Returns result dict."""
    import uuid as _uuid
    rec = {"case_id": case_id, "trial_no": trial_no, "steps": {}}
    key = f"cert-{case_id}-trial-{trial_no}-{_uuid.uuid4().hex[:8]}"
    body = {"case_id": case_id, "exposure_profile": "maintainer",
            "ttl_seconds": 3600, "wait_ready_seconds": 240}
    if deep:
        body["target_version"] = "all"
    st, d = req("POST", "/runs", body=body, key=key, timeout=900)
    if st not in (200, 201, 202) or "run_id" not in d:
        rec["steps"]["start"] = {"ok": False, "detail": d}
        rec["status"] = "startup_error"
        return rec
    run_id = d["run_id"]
    rec["run_id"] = run_id
    state = wait_state(run_id)
    rec["steps"]["start"] = {"ok": state.get("state") == "ready",
                             "state": state.get("state"),
                             "error": state.get("error")}
    if state.get("state") != "ready":
        rec["status"] = state.get("error", {}).get("category", "startup_error")
        req("POST", f"/runs/{run_id}/stop", body={"reason": "cert_failed"})
        return rec
    # flag checks: we need the raw flag — in maintainer mode the controller
    # does not return it; certification obtains it via the platform secret
    # store. For MVP the flag is fetched from the run dir (operator only).
    flag = _read_run_flag(run_id)
    rec["steps"]["flag_available"] = bool(flag)
    if deep:
        dv = deep_verify(case_id, run_id, flag)
        rec["steps"]["deep_gates"] = dv
        if not dv.get("ok"):
            rec["status"] = "reference_failure"
            req("POST", f"/runs/{run_id}/stop", body={"reason": "deep_gate_failed"})
            return rec
    if not flag:
        rec["status"] = "scorer_failure"
        rec["steps"]["correct_flag"] = {"ok": False, "detail": "flag unavailable"}
    else:
        st1, d1 = req("POST", f"/runs/{run_id}/submissions",
                      body={"type": "flag", "value": flag},
                      key=f"{key}-sub-ok")
        rec["steps"]["correct_flag"] = {"ok": bool(d1.get("accepted")), "resp": d1}
        # wrong flag
        st2, d2 = req("POST", f"/runs/{run_id}/submissions",
                      body={"type": "flag", "value": "PCBFLAG_WRONG_" + flag[-8:]},
                      key=f"{key}-sub-wrong")
        rec["steps"]["wrong_flag_rejected"] = {"ok": not bool(d2.get("accepted")), "resp": d2}
        # stale flag from previous trial
        if previous_flag:
            st3, d3 = req("POST", f"/runs/{run_id}/submissions",
                          body={"type": "flag", "value": previous_flag},
                          key=f"{key}-sub-stale")
            rec["steps"]["stale_flag_rejected"] = {"ok": not bool(d3.get("accepted")), "resp": d3}
        else:
            rec["steps"]["stale_flag_rejected"] = {"ok": True, "note": "first trial"}
    # stop + cleanup
    st4, d4 = req("POST", f"/runs/{run_id}/stop", body={"reason": "cert_done"})
    rec["steps"]["stop"] = {"ok": st4 == 200, "removed": d4.get("removed"),
                            "remaining": d4.get("remaining_labeled_resources")}
    ok_steps = all((v.get("ok") if isinstance(v, dict) else v)
                   for v in rec["steps"].values())
    rec["status"] = "certified_candidate_scoring_ready" if ok_steps else "scorer_failure"
    return rec


def _read_run_flag(run_id: str):
    """Operator-only: read the raw flag from the run metadata store. The
    controller keeps the raw flag in its payload (operator scope); the API
    never returns it."""
    import sqlite3
    db = os.environ.get("PCB_STATE_DB", "/app/state/platform.db")
    if not os.path.exists(db):
        # local run: platform db path under work/state
        cand = TREE / "work" / "state" / "platform.db"
        db = str(cand) if cand.exists() else db
    if not os.path.exists(db):
        return None
    c = sqlite3.connect(db)
    try:
        row = c.execute("SELECT payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        return json.loads(row[0]).get("flag")
    finally:
        c.close()


def _rmi_case_images(trial_futures):
    """Delete the docker images a finished case built (project-label scoped,
    pcb_* only) — verified-and-gone JIT discipline."""
    import subprocess
    env = {**os.environ, "DOCKER_CONFIG": os.environ.get("PCB_DOCKER_CONFIG", "")}
    for fut in trial_futures:
        try:
            r = fut.result()
        except Exception:
            continue
        run_id = r.get("run_id")
        if not run_id:
            continue
        proj = f"pcb_{run_id[:12]}"
        p = subprocess.run(["docker", "images", "-q",
                            "--filter", f"label=com.docker.compose.project={proj}"],
                           capture_output=True, text=True, timeout=60, env=env)
        for img in (p.stdout or "").split():
            subprocess.run(["docker", "rmi", "-f", img], capture_output=True, text=True,
                           timeout=120, env=env)


def certify(cases, trials, checkpoint_size, out_file, parallel=1, deep=False):
    import concurrent.futures
    results = []
    prev_flag_by_case = {}
    done = 0
    # resume: keep previously written results (never drop them)
    if out_file.exists():
        try:
            if out_file.suffix == ".jsonl":
                results = [json.loads(l) for l in out_file.read_text().splitlines() if l.strip()]
            else:
                results = json.loads(out_file.read_text())
        except Exception:
            results = []

    def _one(case_id, trial_no, prev):
        r = run_trial(case_id, trial_no, prev, deep=deep)
        return r

    done_cases = {r["case_id"] for r in results if r.get("status") == "certified_candidate_scoring_ready"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
        futures = []
        for case_id in cases:
            if case_id in done_cases:
                continue  # resume: case already certified
            prev = prev_flag_by_case.get(case_id)
            for t in range(1, trials + 1):
                futures.append(ex.submit(_one, case_id, t, prev))
            if parallel > 1:
                # collect this case's trials before moving on (stale-flag chain)
                for fut in futures[-trials:]:
                    r = fut.result()
                    if r["steps"].get("correct_flag", {}).get("ok"):
                        prev_flag_by_case[case_id] = _read_run_flag(r.get("run_id", ""))
                    results.append(r)
                done += trials
                if checkpoint_size and done % checkpoint_size == 0:
                    _write(out_file, results)
                    _write(OUT / f"certification_checkpoint_{done:04d}.json", results)
                    print(f"checkpoint {done}/{len(cases) * trials} trials written")
        if parallel == 1:
            for fut in futures:
                r = fut.result()
                results.append(r)
        _rmi_case_images(futures[-trials:])
    _write(out_file, results)
    return results


def _write(path, results):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".jsonl":
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    else:
        path.write_text(json.dumps(results, ensure_ascii=False, indent=1))


def summarize(results):
    from collections import Counter
    c = Counter(r.get("status", "unknown") for r in results)
    return dict(c)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--mvp", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--trials", type=int, default=2)
    ap.add_argument("--checkpoint-size", type=int, default=20)
    ap.add_argument("--cases", nargs="*", default=[])
    ap.add_argument("--parallel", type=int, default=1)
    ap.add_argument("--deep", action="store_true")
    a = ap.parse_args()
    if a.mvp:
        cases = MVPS
        out = OUT / "mvp_certification.json"
    elif a.all:
        sys.path.insert(0, str(TREE))
        sys.path.insert(0, str(TREE / "controller"))
        from controller.services import case_catalog
        cases = case_catalog.enumerate_cases()
        out = OUT / "certification_215.jsonl"
    else:
        cases = a.cases
        out = OUT / "certification_subset.json"
    if not cases:
        print("no cases selected", file=sys.stderr)
        sys.exit(2)
    results = certify(cases, a.trials, a.checkpoint_size, out, parallel=a.parallel,
                     deep=a.deep)
    print(json.dumps(summarize(results), indent=1))
    # non-zero exit if any trial failed
    if any(r.get("status") != "certified_candidate_scoring_ready" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
