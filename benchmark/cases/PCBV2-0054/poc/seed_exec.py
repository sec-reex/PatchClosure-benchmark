#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Uses `docker run --network <compose-net>` so compose project reconcile cannot
stop the provider (v1 env_failure: container not running after PROVIDER_READY).
v0 hessian2 uses the 2.7.6 image (2.7.8 client -> 2.7.6 = channel closed).
"""
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

PROVIDER_PORT = "20880"
SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
IMAGES = {
    "v0": "pcb/dubbo-serializer-switch:2.7.6",
    "v1": "pcb/dubbo-serializer-switch:2.7.8",
    "v2": "pcb/dubbo-serializer-switch:2.7.12",
}

X = os.environ.get("PCB_X") or os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
HERE = Path(__file__).resolve().parent.parent


def _compose(*args, timeout=60, profile=None):
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "")
    ver = os.environ.get("VERSION", "")
    cmd = ["docker", "compose"]
    if proj:
        cmd += ["-p", proj]
    if profile:
        cmd += ["--profile", profile]
    elif ver:
        cmd += ["--profile", ver]
    cmd += list(args)
    return subprocess.run(
        cmd, cwd=str(HERE), text=True, capture_output=True, check=False, timeout=timeout,
        env=os.environ.copy(),
    )


def _provider_cid(version):
    svc = SERVICE[version]
    r = _compose("ps", "-aq", svc, profile=version)
    for line in (r.stdout or "").splitlines():
        if line.strip():
            return line.strip()
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "")
    guess = f"{proj}-{svc}-1" if proj else ""
    if guess:
        r2 = subprocess.run(
            ["docker", "inspect", "-f", "{{.Id}}", guess],
            text=True, capture_output=True, check=False,
        )
        if r2.returncode == 0 and (r2.stdout or "").strip():
            return guess
    return ""


def _attach_network(version):
    cid = _provider_cid(version)
    if cid:
        r = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", cid],
            text=True, capture_output=True, check=False,
        )
        nets = (r.stdout or "").split()
        if nets:
            return nets[0]
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "")
    for cand in (f"{proj}_default", f"{proj}-default"):
        r = subprocess.run(
            ["docker", "network", "inspect", cand],
            text=True, capture_output=True, check=False,
        )
        if r.returncode == 0:
            return cand
    return ""


def _image_for(version, ser):
    # Same-version consumer for hessian2@v0 (codec/heartbeat skew otherwise).
    # Residual native-hessian needs 2.7.8+ (id-10 codec).
    if ser == "hessian2" and version == "v0":
        return IMAGES["v0"]
    return IMAGES.get(version, IMAGES["v1"])


def _logs(version):
    svc = SERVICE[version]
    r = _compose("logs", "--no-log-prefix", svc, profile=version)
    text = (r.stdout or "") + (r.stderr or "")
    cid = _provider_cid(version)
    if cid:
        r2 = subprocess.run(
            ["docker", "logs", "--tail", "400", cid],
            text=True, capture_output=True, check=False,
        )
        text += (r2.stdout or "") + (r2.stderr or "")
    return text


def _docker_run_client(version, ser):
    img = _image_for(version, ser)
    net = _attach_network(version)
    if not net:
        return subprocess.CompletedProcess(
            args=[], returncode=20, stdout="", stderr="env: provider network missing",
        )
    insp = subprocess.run(
        ["docker", "image", "inspect", img],
        text=True, capture_output=True, check=False,
    )
    if insp.returncode != 0:
        return subprocess.CompletedProcess(
            args=[], returncode=20, stdout="", stderr=f"env: image missing {img}",
        )
    svc = SERVICE[version]
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "pcb")
    name = f"{proj}-atk-{version}-{uuid.uuid4().hex[:8]}"
    inner = (
        "java -Xms32m -Xmx256m -XX:+UseSerialGC "
        "-Dpcb.role=client -Ddubbo.application.qos.enable=false "
        "-Djava.net.preferIPv4Stack=true "
        '-cp "$(cat /work/cp.txt)" com.pcb.Client '
        + svc + " " + PROVIDER_PORT + " " + ser
    )
    cmd = [
        "docker", "run", "--rm", "--restart=no",
        "--name", name,
        "--network", net,
        "-e", "PCB_FLAG=noflag",
        img,
        "sh", "-c", inner,
    ]
    try:
        return subprocess.run(
            cmd, cwd=str(HERE), text=True, capture_output=True, check=False, timeout=90,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as e:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1,
            stdout=e.stdout or "", stderr=(e.stderr or "") + "\ntimeout",
        )


def run_probe(candidate, *, version="v1"):
    if version not in SERVICE:
        return {"version": version, "X": "", "env_error": True, "error": "bad version"}
    if not isinstance(candidate, dict):
        candidate = {"serialization": str(candidate)}
    ser = str(candidate.get("serialization", "hessian2"))
    before = _logs(version)
    client_out = ""
    env_error = False
    last_rc = 1
    for _attempt in range(4):
        r = _docker_run_client(version, ser)
        last_rc = r.returncode
        client_out = (r.stdout or "") + (r.stderr or "")
        if "env:" in (r.stderr or "") and r.returncode == 20:
            env_error = True
            break
        time.sleep(3)
        after = _logs(version)
        flag_hit = X if X in after else ""
        if not flag_hit and X in client_out:
            # provider log is the oracle; client must stay silent
            flag_hit = ""
        if flag_hit or (r.returncode == 0 and client_out.strip()):
            result_line = ""
            for line in client_out.strip().splitlines():
                if line.strip().startswith("{"):
                    result_line = line.strip()
            return {
                "version": version,
                "id": candidate.get("id"),
                "serialization": ser,
                "client_result": result_line,
                "X": flag_hit,
            }
        time.sleep(3)
        before = after
    result_line = ""
    for line in client_out.strip().splitlines():
        if line.strip().startswith("{"):
            result_line = line.strip()
    after = _logs(version)
    flag_hit = X if X in after else ""
    return {
        "version": version,
        "id": candidate.get("id"),
        "serialization": ser,
        "client_result": result_line,
        "X": flag_hit,
        "env_error": env_error,
        "client_rc": last_rc,
    }


if __name__ == "__main__":
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    try:
        cand = json.load(open(sys.argv[1]))
        r = run_probe(cand, version=version)
        print(json.dumps(r, default=str))
    except Exception as e:
        print(json.dumps({"version": version, "X": "", "env_error": True, "error": str(e)}))
        sys.exit(0)
