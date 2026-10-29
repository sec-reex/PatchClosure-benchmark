#!/usr/bin/env python3
"""run_mvp.py — Round 24 v2 MVP 认证编排（7 family 代表 case × N trials）。

每 case-trial 由两个 run 组成门对：
  run A (target_version=v0): seed 期望 effect_observed；wrong/stale flag 期望拒绝
  run B (target_version=v1): seed 期望 effect_not_observed(blocked)；residual 期望 observed
认证状态写 append-only runtime_trials.jsonl；非零退出暴露失败。

用法：python3 tools/run_mvp.py --trials 2 [--cases PCBV2-0002,PCBV2-0086] [--api http://127.0.0.1:8787]
"""
import argparse
import json
import subprocess
import sys
import time
import uuid
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
TRIALS_LOG = REPORTS / "runtime_trials.jsonl"  # 可用 --out 覆盖（并行时各 agent 独立文件）

MVP_CASES = ["PCBV2-0002", "PCBV2-0086", "PCBV2-0018", "PCBV2-0084",
             "PCBV2-0142", "PCBV2-0015", "PCBV2-0054"]


def api(api_base: str, method: str, path: str, body=None, timeout: int = 600):
    url = f"{api_base}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode()[:300]}


def wait_run(api_base: str, run_id: str, states, timeout_s: int = 1500):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = api(api_base, "GET", f"/api/v1/runs/{run_id}")
        if r.get("state") in states:
            return r
        time.sleep(5)
    return api(api_base, "GET", f"/api/v1/runs/{run_id}")


def docker_residue(project: str) -> int:
    p = subprocess.run(["docker", "ps", "-a", "--filter", f"name={project}",
                        "--format", "{{.Names}}"], capture_output=True, text=True, timeout=30)
    return len([l for l in (p.stdout or "").splitlines() if l.strip()])


def run_gate(api_base: str, cid: str, trial_no: int, version: str,
             stale_flag: str, idem_tag: str) -> dict:
    """单个版本 run 的门检查；返回 {seed_rc, seed_outcome, wrong_rc, stale_rc, ...}。"""
    run_key = f"mvp-{idem_tag}-{cid}-t{trial_no}-{version}-{uuid.uuid4().hex[:6]}"
    rid = api(api_base, "POST", "/api/v1/runs", {
        "case_id": cid, "target_version": version, "trial_id": f"t{trial_no}",
        "idempotency_key": run_key})
    if rid.get("_http_error"):
        return {"run_id": "", "error": f"create_run {rid.get('_http_error')}: {rid.get('_body')}"}
    rid = rid["run_id"]
    r = wait_run(api_base, rid, {"ready", "error"})
    if r["state"] == "error":
        return {"run_id": rid, "error": f"{r.get('error', {}).get('category')}: {r.get('error', {}).get('detail', '')[:200]}"}

    def submit(mode, override=""):
        return api(api_base, "POST", f"/api/v1/runs/{rid}/submissions", {
            "type": "verify", "mode": mode, "flag_override": override,
            "idempotency_key": f"{run_key}-{mode}-{override[:12]}"}, timeout=900)

    # wrong/stale 的验证模式：case.yaml verification.wrong_flag_mode（默认 seed）
    import yaml as _yaml
    wm = "seed"
    try:
        cm = _yaml.safe_load((ROOT / "cases" / cid / "case.yaml").read_text())
        wm = (cm.get("verification") or {}).get("wrong_flag_mode", "seed")
    except Exception:
        pass
    s_seed = submit("seed")
    s_wrong = submit(wm, "PCBFLAG_WRONG_000000000000")
    s_stale = None
    if stale_flag:
        s_stale = submit(wm, stale_flag)
    s_res = submit("residual") if version == "v1" else None
    res = {"run_id": rid, "version": version,
           "seed_outcome": s_seed.get("outcome"), "seed_rc": s_seed.get("rc"),
           "wrong_outcome": s_wrong.get("outcome"),
           "stale_outcome": s_stale.get("outcome") if s_stale else None,
           "residual_outcome": s_res.get("outcome") if s_res else None}
    # stop + 残留检查
    st = api(api_base, "POST", f"/api/v1/runs/{rid}/stop", {})
    res["stop_state"] = st.get("state")
    proj = f"pcb_{rid[4:16]}"
    res["residue_after_stop"] = docker_residue(proj)
    return res


def trial(cid: str, trial_no: int, stale_flag: str, api_base: str, idem_tag: str) -> dict:
    g0 = run_gate(api_base, cid, trial_no, "v0", stale_flag, idem_tag)
    g1 = run_gate(api_base, cid, trial_no, "v1", stale_flag, idem_tag)
    # v0 flag（供下一 trial 当 stale）
    v0_flag = ""
    v1_flag = ""
    if g0.get("run_id"):
        rr = api(api_base, "GET", f"/api/v1/runs/{g0['run_id']}")
        v0_flag = rr.get("flag", "")
    if g1.get("run_id"):
        rr = api(api_base, "GET", f"/api/v1/runs/{g1['run_id']}")
        v1_flag = rr.get("flag", "")
    print(f"    [flags] v0={v0_flag[:14]}... v1={v1_flag[:14]}...")
    ok = (
        g0.get("seed_outcome") == "effect_observed"
        and g0.get("wrong_outcome") == "effect_not_observed"
        and (g0.get("stale_outcome") in (None, "effect_not_observed"))
        and g1.get("seed_outcome") == "effect_not_observed"
        and g1.get("residual_outcome") == "effect_observed"
        and g0.get("stop_state") == "stopped" and g1.get("stop_state") == "stopped"
        and g0.get("residue_after_stop", 1) == 0 and g1.get("residue_after_stop", 1) == 0
    )
    return {"case_id": cid, "trial_no": trial_no, "status": "certified" if ok else "failed",
            "v0": g0, "v1": g1, "v0_flag": v0_flag}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2)
    ap.add_argument("--cases", default=",".join(MVP_CASES))
    ap.add_argument("--api", default="http://127.0.0.1:8787")
    ap.add_argument("--idem-tag", default="r24v2")
    ap.add_argument("--out", default=None, help="独立输出 jsonl（并行时避免互相覆盖）")
    args = ap.parse_args()
    if args.out:
        TRIALS_LOG = Path(args.out)
    REPORTS.mkdir(parents=True, exist_ok=True)
    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    results = []
    for cid in cases:
        stale = ""
        for t in range(1, args.trials + 1):
            tr = trial(cid, t, stale, args.api, args.idem_tag)
            stale = tr.get("v0_flag", "")  # 下一 trial 的 stale flag
            results.append(tr)
            with TRIALS_LOG.open("a") as f:
                f.write(json.dumps(tr, ensure_ascii=False, default=str) + "\n")
            print(f"[{cid}] trial{t}: {tr['status']} "
                  f"(v0 seed={tr['v0'].get('seed_outcome')} wrong={tr['v0'].get('wrong_outcome')} "
                  f"stale={tr['v0'].get('stale_outcome')} | "
                  f"v1 seed={tr['v1'].get('seed_outcome')} residual={tr['v1'].get('residual_outcome')} "
                  f"residue={tr['v1'].get('residue_after_stop')})")
            if tr["status"] != "certified" and not args.cases:
                break
    n_ok = sum(1 for r in results if r["status"] == "certified")
    print(f"\nMVP result: {n_ok}/{len(results)} trials certified")
    sys.exit(0 if n_ok == len(results) else 1)


if __name__ == "__main__":
    main()
