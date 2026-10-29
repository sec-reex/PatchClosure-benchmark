#!/usr/bin/env python3
"""cleanup_case_images.py — 按 case 删除其 compose 定义的自建 pcb-* 镜像（验证完即删铁律）。

只删 repo 以 pcb- 或 pcb/ 开头的本地构建镜像；上游基础镜像（httpd/python/node/mariadb 等）
保留（其他 case 可能共用）。用法：
  python3 tools/cleanup_case_images.py PCBV2-0002,PCBV2-0015 ...
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"


def case_images(cid: str):
    """解析 case 的 docker-compose.yml，返回 image 名集合（repo:tag）。"""
    imgs = set()
    cf = CASES / cid / "docker-compose.yml"
    if not cf.exists():
        return imgs
    txt = cf.read_text(encoding="utf-8", errors="ignore")
    for m in re.finditer(r'^\s*image:\s*["\']?([^"\'\s#]+)', txt, re.M):
        imgs.add(m.group(1).strip())
    return imgs


def local_images():
    out = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                         capture_output=True, text=True).stdout
    return set(l.strip() for l in out.splitlines() if l.strip())


def main():
    ids = sys.argv[1].split(",") if len(sys.argv) > 1 else []
    if not ids:
        print("用法: cleanup_case_images.py <case_id[,case_id...]>", file=sys.stderr)
        sys.exit(2)
    local = local_images()
    to_delete = []
    for cid in ids:
        for img in case_images(cid):
            if (img.startswith("pcb-") or img.startswith("pcb/")) and img in local:
                to_delete.append((cid, img))
    if not to_delete:
        print("无可删的 pcb-* 镜像（上游镜像保留）")
        return
    print("待删除：")
    for cid, img in to_delete:
        print(f"  {cid}: {img}")
    # 删除（带标签引用；同时清理无标签 dangling 由 prune 兜底）
    for cid, img in to_delete:
        r = subprocess.run(["docker", "rmi", img], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  ✓ {img}")
        else:
            print(f"  ✗ {img}: {r.stderr.strip()[:120]}")
    print(f"完成，删除 {len(to_delete)} 个镜像引用")


if __name__ == "__main__":
    main()
