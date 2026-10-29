#!/usr/bin/env python3
"""rerun_batch.py — 批量重跑认证（run_mvp.py 单 case 封装），认证后按铁律删除该 case 镜像。

用法：
  python3 tools/rerun_batch.py --cases PCBV2-0019,PCBV2-0020 --out reports/rerun_1.jsonl
  python3 tools/rerun_batch.py --cases-file /tmp/cases.txt --out reports/rerun_1.jsonl --trials 2

行为：
  1. 逐 case 调 run_mvp.py --trials N --cases <cid> --out <out>（隔离输出，append-only）
  2. 每个 case 结束（成功或失败）都跑 cleanup_case_images.py（pcb-* JIT 删除）
  3. 每 case 后清理 dangling 镜像 + 停止容器 + 匿名卷 + 写进度到 <out>.progress
  4. 磁盘水位 <15GB 时暂停等待
  5. 已在 <out>.progress 里的 case 自动跳过（可安全重启）
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def disk_free_gb() -> float:
    r = shutil.disk_usage(str(ROOT))
    return r.free / (1024 ** 3)


def run(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="")
    ap.add_argument("--cases-file", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--trials", type=int, default=2)
    ap.add_argument("--api", default="http://127.0.0.1:8787")
    ap.add_argument("--disk-floor", type=float, default=15.0)
    args = ap.parse_args()

    cases = []
    if args.cases:
        cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    if args.cases_file:
        cases += [l.strip() for l in Path(args.cases_file).read_text().splitlines() if l.strip()]
    cases = sorted(set(cases))
    if not cases:
        print("no cases", file=sys.stderr)
        sys.exit(2)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    prog = Path(str(out) + ".progress")
    already = set()
    if prog.exists():
        for line in prog.read_text().splitlines():
            cid0 = line.split("\t")[0].strip()
            if cid0:
                already.add(cid0)
    if already:
        n_skip = len(already & set(cases))
        cases = [c for c in cases if c not in already]
        print(f"rerun_batch: skip {n_skip} already in {prog.name}, remain {len(cases)}")
    print(f"rerun_batch: {len(cases)} cases -> {out}")

    for i, cid in enumerate(cases, 1):
        while disk_free_gb() < args.disk_floor:
            print(f"  disk {disk_free_gb():.1f}GB < {args.disk_floor}GB, wait 60s", flush=True)
            time.sleep(60)
        print(f"[{i}/{len(cases)}] {cid} start {time.strftime('%H:%M:%S')}", flush=True)
        t0 = time.time()
        r = run([sys.executable, str(TOOLS / "run_mvp.py"),
                 "--trials", str(args.trials), "--cases", cid,
                 "--out", str(out), "--api", args.api])
        dt = int(time.time() - t0)
        # 解析该 case 本次结果
        n_cert = 0
        n_trials = 0
        try:
            for line in out.read_text().splitlines():
                rec = json.loads(line)
                if rec.get("case_id") == cid:
                    n_trials += 1
                    if rec.get("status") == "certified":
                        n_cert += 1
        except Exception:
            pass
        ok = (n_cert >= args.trials)
        with prog.open("a") as f:
            f.write(f"{cid}\t{'CERTIFIED' if ok else 'FAILED'}\t{n_cert}/{n_trials}\t{dt}s\t"
                    f"rc={r.returncode}\n")
        print(f"[{i}/{len(cases)}] {cid} -> {'CERTIFIED' if ok else 'FAILED'} "
              f"({n_cert}/{n_trials}, {dt}s)", flush=True)
        if not ok:
            try:
                subprocess.run([sys.executable, str(TOOLS / "sync_live_failures.py")],
                               capture_output=True, timeout=30)
            except Exception:
                pass
        # JIT: 成功失败都删本 case 的 pcb-* 镜像，否则 FAILED 会把盘撑满。
        run([sys.executable, str(TOOLS / "cleanup_case_images.py"), cid])
        subprocess.run(["docker", "image", "prune", "-f"], capture_output=True)
        subprocess.run(["docker", "container", "prune", "-f"], capture_output=True)
        subprocess.run(["docker", "volume", "prune", "-f"], capture_output=True)

    n_ok = 0
    try:
        for line in prog.read_text().splitlines():
            if "\tCERTIFIED\t" in line:
                n_ok += 1
    except Exception:
        pass
    print(f"rerun_batch done: {n_ok}/{len(cases)} certified (see {prog})")
    sys.exit(0)


if __name__ == "__main__":
    main()
