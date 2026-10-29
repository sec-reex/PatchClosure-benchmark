#!/usr/bin/env python3
"""batch_cases.py — 端口感知分批：把 case 分成 N 组，每组内 compose host 端口互不冲突
（供并行认证：每个子 agent 跑一组，组内串行、组间并行）。"""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"


def case_ports(cid: str) -> set:
    comp = CASES / cid / "docker-compose.yml"
    if not comp.exists():
        return set()
    text = comp.read_text(errors="ignore")
    return {int(m.group(1)) for m in re.finditer(r'["\']?(\d{4,5}):\d+["\']?', text)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--groups", type=int, default=4, help="组数（并行度）")
    ap.add_argument("--limit", type=int, default=0, help="只取前 N 个 case（0=全部）")
    ap.add_argument("--start", type=int, default=0, help="跳过前 M 个 case（分批续跑）")
    ap.add_argument("--only", default="", help="只分组这些 case（逗号分隔）")
    args = ap.parse_args()
    ids = sorted(p.name for p in CASES.iterdir() if (p / "case.yaml").exists())
    if args.only:
        ids = [c for c in args.only.split(",") if c in ids]
    ids = ids[args.start:]
    if args.limit:
        ids = ids[: args.limit]
    # 贪心分组：每组端口唯一
    groups = [set() for _ in range(args.groups)]
    group_ports = [set() for _ in range(args.groups)]
    for cid in ids:
        ports = case_ports(cid)
        # 平衡贪心：按负载升序尝试放置（端口不冲突即可）
        order = sorted(range(args.groups), key=lambda k: (len(groups[k]), k))
        for i in order:
            if ports.isdisjoint(group_ports[i]):
                groups[i].add(cid)
                group_ports[i] |= ports
                break
        else:
            # 全冲突：放入最小负载组（组内运行时串行）
            groups[order[0]].add(cid)
            group_ports[order[0]] |= ports
    for i, g in enumerate(groups):
        print(f"group{i}: {len(g)} cases")
        print("  " + ",".join(sorted(g)))


if __name__ == "__main__":
    main()
