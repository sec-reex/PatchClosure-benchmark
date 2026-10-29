#!/usr/bin/env python3
"""disk_watchdog.py — 周期清理：停止容器 + 已完成 case 镜像 + dangling + build cache。

用法：python3 tools/disk_watchdog.py [--interval 600] [--floor-gb 15]
在后台循环运行；每 interval 秒清理一次。保留正在跑批次的活跃 case 镜像。
"""
import argparse
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
LISTS = Path("/tmp/rerun_lists")


def host_free_gb():
    import shutil
    return shutil.disk_usage(str(ROOT)).free / (1024 ** 3)


def active_cases():
    """活跃 case：各批次未处理完的 + 运行中容器引用的。"""
    active = set()
    for name in ("fA", "fB", "fC", "fD", "svcA", "svcB", "svcC", "svcD",
                 "v0a", "v0b", "rerunA", "rerunB", "rerunC"):
        done = set()
        p = REPORTS / f"{name}.jsonl.progress"
        if p.exists():
            for l in p.read_text().splitlines():
                if l.strip():
                    done.add(l.split("\t")[0])
        pf = LISTS / f"{name}.txt"
        if pf.exists():
            allc = set(l.strip() for l in open(pf) if l.strip())
            active |= (allc - done)
    # live 215 sweep: group lists + progress
    for pf in sorted(REPORTS.glob("live215_group*.cases")):
        allc = set(l.strip() for l in pf.read_text().splitlines() if l.strip())
        prog = REPORTS / (pf.name.replace(".cases", ".jsonl.progress"))
        if prog.exists():
            for l in prog.read_text().splitlines():
                if l.strip():
                    done.add(l.split("\t")[0])
        active |= (allc - done)
    out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                         capture_output=True, text=True).stdout
    for n in out.splitlines():
        m = re.search(r"(\d{4})", n)
        if m:
            active.add(f"PCBV2-{m.group(1)}")
    return active


def cleanup(floor_gb: float):
    # 0) Running 态僵尸容器：DB state 非活跃（error/stopped/expired/无记录）或运行超 30 分钟
    import sqlite3
    try:
        db = sqlite3.connect(str(ROOT / "work/state/platform_v2.db"))
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}|{{.Status}}"],
                             capture_output=True, text=True).stdout
        import re as _re
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) != 2:
                continue
            name, status = parts
            m = _re.search(r"Up (\d+) (minute|hour|day)s?", status)
            age_min = 0
            if m:
                val, unit = int(m.group(1)), m.group(2)
                age_min = val if unit == "minute" else val * 60 if unit == "hour" else val * 1440
            is_zombie = False
            mm = _re.match(r"pcb_run_([0-9a-f]+)-", name)
            if mm:
                prefix = "run_" + mm.group(1)
                row = db.execute("SELECT state FROM runs WHERE run_id LIKE ?",
                                 (prefix + "%",)).fetchone()
                if row is None or row[0] in ("error", "stopped", "expired"):
                    is_zombie = True
                elif age_min > 30:
                    is_zombie = True  # DB 说 ready/scoring 但超 30 分钟 = 僵尸
            elif name.startswith("pcb-") and age_min > 30:
                is_zombie = True
            if is_zombie:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        db.close()
    except Exception:
        pass
    # 1) 停止/创建态容器
    out = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}} {{.Status}}"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "Exited" in line or "Created" in line:
            name = line.split()[0]
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    # 1.5) 僵尸网络：无容器的 pcb_run_* 网络（run 结束残留）
    out = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"],
                         capture_output=True, text=True).stdout
    for name in out.splitlines():
        name = name.strip()
        if name.startswith("pcb_run_"):
            cnt = subprocess.run(
                ["docker", "network", "inspect", name, "--format", "{{len .Containers}}"],
                capture_output=True, text=True).stdout.strip()
            if cnt == "0":
                subprocess.run(["docker", "network", "rm", name], capture_output=True)
    # 2) build cache + dangling（保留活跃构建）
    subprocess.run(["docker", "builder", "prune", "-f", "--filter", "until=30m"],
                   capture_output=True)
    subprocess.run(["docker", "image", "prune", "-f"], capture_output=True)
    # 3) 已完成 case 的 pcb-* 镜像
    active = active_cases()
    img_case = {}
    for cdir in (ROOT / "cases").glob("PCBV2-*"):
        t = (cdir / "docker-compose.yml").read_text(errors="ignore")
        for m in re.finditer(r'image:\s*"?([^"\s#]+)', t):
            img_case.setdefault(m.group(1).strip(), cdir.name)
    out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                         capture_output=True, text=True).stdout
    to_del = []
    for img in out.splitlines():
        img = img.strip()
        if not (img.startswith("pcb-") or img.startswith("pcb/")):
            continue
        case = img_case.get(img)
        if case and case not in active:
            to_del.append(img)
    for i in range(0, len(to_del), 30):
        subprocess.run(["docker", "rmi", "-f"] + to_del[i:i + 30], capture_output=True)
    return len(to_del)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=600)
    ap.add_argument("--floor-gb", type=float, default=15.0)
    args = ap.parse_args()
    print(f"disk_watchdog: interval={args.interval}s floor={args.floor_gb}GB", flush=True)
    while True:
        try:
            n = cleanup(args.floor_gb)
            print(f"[{time.strftime('%H:%M:%S')}] 清理 {n} 个镜像, 磁盘 {host_free_gb():.1f}GB", flush=True)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] 清理异常: {e}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
