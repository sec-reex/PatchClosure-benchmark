#!/usr/bin/env python3
r"""Flag differential oracle for gotenberg-cve-2026-40281.

Pair: CVE-2026-42589 (ExifTool metadata KEY pseudo-tag injection; fixed v8.30.1)
   -> CVE-2026-40281 (ExifTool metadata VALUE newline argument injection; fixed
      v8.31.0). The v8.30.1 fix sanitized only the metadata KEY side of the
      go-exiftool `-<key>=<value>` line, leaving VALUES injectable == incomplete.

REAL official gotenberg images, one per version profile, driven over
unauthenticated HTTP POST /forms/pdfengines/metadata/write:

  V0 = gotenberg/gotenberg:8.29.1  (dangerousTags = {FileName,Directory}, EXACT
                                    case-sensitive delete -> both KEY & VALUE open)
  V1 = gotenberg/gotenberg:8.30.1  (CVE-2026-42589 fix: dangerousTags EqualFold,
                                    +SymLink/HardLink -> KEY blocked, VALUE OPEN = TARGET)
  V2 = gotenberg/gotenberg:8.31.0  (CVE-2026-40281 fix: validateMetadataValue
                                    rejects \n\r\x00 in values -> VALUE blocked)

BENIGN argument-injection canary (state-write): each payload injects the ExifTool
`-FileName=<sentinel>` pseudo-tag, which renames the uploaded temp PDF to a
per-run sentinel path /tmp/pcb_{key,val}_${PCB_FLAG}. Detection = that sentinel
file EXISTS in the container (checked via `docker compose exec`). The moved file
is the original %PDF -- no `-if`/`-exec`/shell, no real RCE.

Gate (all four must hold for a clean incomplete-fix):
  original_poc_reaches_flag_on_v0  : KEY injection renames PDF @ V0
  original_poc_blocked_on_v1       : KEY injection blocked (key blocklist) @ V1
  bypass_poc_reaches_flag_on_v1    : VALUE injection renames PDF @ V1   <- TARGET residual
  bypass_blocked_on_v2             : VALUE injection blocked (value check) @ V2

Usage (bring the three profiles up first):
  docker compose -p pcb-gotenberg40281 up -d
  PCB_FLAG=$(openssl rand -hex 6) python3 oracle.py --gate
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "_heldout"))
import original_poc  # noqa: E402
import bypass_poc  # noqa: E402

COMPOSE_PROJECT = "pcb-gotenberg40281"
PDF = HERE / "sample.pdf"

PROFILES = {
    "v0": {"port": 3010, "service": "v0", "image": "gotenberg/gotenberg:8.29.1"},
    "v1": {"port": 3011, "service": "v1", "image": "gotenberg/gotenberg:8.30.1"},
    "v2": {"port": 3012, "service": "v2", "image": "gotenberg/gotenberg:8.31.0"},
}
ENDPOINT = "/forms/pdfengines/metadata/write"


def _multipart(metadata: str) -> tuple[bytes, str]:
    boundary = "----pcb" + secrets.token_hex(8)
    pdf = PDF.read_bytes()
    parts = []
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        b'Content-Disposition: form-data; name="files"; filename="sample.pdf"\r\n'
        b"Content-Type: application/pdf\r\n\r\n"
    )
    parts.append(pdf + b"\r\n")
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(b'Content-Disposition: form-data; name="metadata"\r\n\r\n')
    parts.append(metadata.encode() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


def send(profile: str, metadata: str, timeout: int = 30) -> int:
    """POST the metadata-write request; return HTTP status (0 on transport err)."""
    port = PROFILES[profile]["port"]
    body, boundary = _multipart(metadata)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{ENDPOINT}",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def sentinel_exists(profile: str, path: str) -> bool:
    """True iff the sentinel file exists in the running container (state-write)."""
    svc = PROFILES[profile]["service"]
    r = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", svc,
         "sh", "-c", f"test -e '{path}' && echo YES || echo no"],
        capture_output=True, text=True,
    )
    return "YES" in r.stdout


def probe(profile: str, poc_mod, flag: str) -> dict:
    """Fire one injection payload against one version; report status + sentinel."""
    cand = poc_mod.candidate(flag)
    # ensure no stale sentinel (unique per-run flag makes this belt-and-braces)
    svc = PROFILES[profile]["service"]
    subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "exec", "-T", svc,
         "sh", "-c", f"rm -f '{cand['sentinel']}' 2>/dev/null || true"],
        capture_output=True, text=True,
    )
    status = send(profile, cand["metadata"])
    reached = sentinel_exists(profile, cand["sentinel"])
    return {"kind": cand["kind"], "http": status, "sentinel": cand["sentinel"],
            "reached_flag": reached}


def gate() -> dict:
    flag = os.environ.get("PCB_FLAG") or secrets.token_hex(6)

    orig_v0 = probe("v0", original_poc, flag)
    orig_v1 = probe("v1", original_poc, flag)
    byp_v1 = probe("v1", bypass_poc, flag)
    byp_v2 = probe("v2", bypass_poc, flag)
    # extra evidence
    orig_v2 = probe("v2", original_poc, flag)
    byp_v0 = probe("v0", bypass_poc, flag)

    g = {
        "original_poc_reaches_flag_on_v0": orig_v0["reached_flag"] is True,
        "original_poc_blocked_on_v1": orig_v1["reached_flag"] is False,
        "bypass_poc_reaches_flag_on_v1": byp_v1["reached_flag"] is True,
        "bypass_blocked_on_v2": byp_v2["reached_flag"] is False,
        # supporting
        "original_blocked_on_v2": orig_v2["reached_flag"] is False,
        "residual_reaches_on_v0": byp_v0["reached_flag"] is True,
        "distinct_fixed_versions": True,  # 8.30.1 (key) != 8.31.0 (value)
    }
    g["passed"] = all([
        g["original_poc_reaches_flag_on_v0"],
        g["original_poc_blocked_on_v1"],
        g["bypass_poc_reaches_flag_on_v1"],
        g["bypass_blocked_on_v2"],
    ])
    return {
        "flag": flag,
        "probes": {
            "original@v0": orig_v0, "original@v1": orig_v1, "original@v2": orig_v2,
            "residual@v0": byp_v0, "residual@v1": byp_v1, "residual@v2": byp_v2,
        },
        "gate": g,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true", help="run full differential gate")
    args = ap.parse_args()
    if not args.gate:
        ap.print_help()
        return 2
    result = gate()
    print(json.dumps(result, indent=2))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
