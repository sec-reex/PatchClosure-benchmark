#!/usr/bin/env python3
"""POST a candidate tar to the running plexus-archiver /extract service."""
import json
import os
import sys
import base64
import urllib.error
import urllib.request


def http_extract(port, tar_bytes, timeout=30):
    url = f"http://127.0.0.1:{int(port)}/extract"
    req = urllib.request.Request(
        url,
        data=tar_bytes,
        method="POST",
        headers={"Content-Type": "application/x-tar"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return -1, f"HTTP_ERROR {type(e).__name__}: {e}"


def run_probe(candidate, version="v1"):
    if not isinstance(candidate, dict):
        candidate = {"tar_b64": str(candidate)}
    tar_bytes = base64.b64decode(candidate.get("tar_b64", "").strip() or b"")
    port = os.environ.get("PCB_TARGET_PORT")
    if not port:
        raise SystemExit("PCB_TARGET_PORT is required")
    status, resp = http_extract(port, tar_bytes)
    expect = os.environ.get("PCB_X") or os.environ.get("RUN_FLAG_REF") or os.environ.get("RUN_FLAG") or ""
    flag_hit = expect if expect and expect in resp else ""
    parsed = {}
    for line in reversed(resp.strip().splitlines()):
        try:
            parsed = json.loads(line)
            break
        except Exception:
            continue
    return {
        "version": version,
        "id": candidate.get("id"),
        "http_status": status,
        "witness": parsed.get("witness"),
        "error": parsed.get("error"),
        "X": flag_hit,
        "resp_snip": resp[:200],
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
