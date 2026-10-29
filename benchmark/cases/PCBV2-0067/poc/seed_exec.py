#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

External client container joins the same compose project and connects to
service v0/v1 by Docker DNS on TCP 9009 (not a hardcoded host port).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLIENT_CMD = 'java -cp "$(cat /work/cp.txt)" Client'
SERVER_PORT = "9009"
SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
HERE = Path(__file__).resolve().parent
CASE_DIR = HERE.parent


def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"


X = os.environ.get("PCB_X") or new_flag()


def _compose(*args, env=None, timeout=None):
    project = os.environ.get("COMPOSE_PROJECT_NAME")
    cmd = ["docker", "compose"]
    if project:
        cmd += ["-p", project]
    cmd += ["--project-directory", str(CASE_DIR), *args]
    return subprocess.run(
        cmd,
        cwd=str(CASE_DIR),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def run_probe(candidate, *, version="v1"):
    svc = SERVICE[version]
    if not isinstance(candidate, dict):
        candidate = {"mode": str(candidate)}
    mode = candidate.get("mode", "direct")

    r = _compose(
        "--profile", "client", "run", "--rm", "--no-deps", "client",
        "sh", "-c", f"{CLIENT_CMD} {svc} {SERVER_PORT} {mode}",
        env={"PCB_X": X, "PCB_FLAG": os.environ.get("PCB_FLAG", X)},
        timeout=120,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 and "CLIENT_RESP=" not in out:
        raise RuntimeError(out[-800:] or f"compose run client failed rc={r.returncode}")
    flag_hit = X if X in out else ""
    resp = ""
    for line in out.splitlines():
        if line.startswith("CLIENT_RESP="):
            resp = line[len("CLIENT_RESP="):]
            break
    return {
        "version": version,
        "id": candidate.get("id"),
        "mode": mode,
        "resp": resp,
        "X": flag_hit,
        "raw": out[-600:],
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
