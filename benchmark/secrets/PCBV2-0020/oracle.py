#!/usr/bin/env python3
"""Flag differential oracle for n8n-cve-2026-44791.

Chain: CVE-2026-42232 (XML node prototype pollution -> RCE, fixed 2.17.4/1.123.32 by
       sanitizeXmlName tag/attr processors + attrkey/charkey validation)
     -> CVE-2026-44791 (coercion TOCTOU bypass of the attrkey/charkey validation,
        fixed 2.20.7 by mutating options with the stable coerced string).

V0 = n8n 2.17.3  (no sanitizer, no validation)
V1 = n8n 2.20.6  (sanitizeXmlName + validation-on-copy; raw attrkey reaches the parser)
V2 = n8n 2.20.7  (options.attrkey = String(options.attrkey) before the parser sees it)

seed:     webhook XML `<root><__proto__><pcb_seed_flag>FLAG</pcb_seed_flag></__proto__></root>`
          -> V0: deepCopy turns the own '__proto__' key into the item prototype,
                 `$json.root[1].pcb_seed_flag` exfils FLAG to the sidecar
          -> V1: tag sanitized, no pollution
residual: Function node (vm2, main process) builds a stateful-toString object and feeds it
          to the XML node options.attrkey via an expression; xml2js re-coerces it to
          '__proto__' -> defineProperty onto Object.prototype (pcb_res_flag = FLAG)
          -> V1: validation checked a copy ('safe') but the parser used the raw object
          -> V2: options.attrkey mutated to the stable string, no pollution
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from flag_oracle import contains_flag, validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
import n8n_util as u  # noqa: E402

sys.path.insert(0, str(HERE / "_heldout"))
from bypass_poc import bypass_poc  # noqa: E402
from original_poc import original_poc  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
HITS_FILE = str(HERE / "sidecar_hits.json")


def _restart(version: str, timeout: int = 180) -> bool:
    # n8n 2.17.3 (v0) crashes on `docker restart` because SQLite migration
    # UpdateParentFolderIdColumn1740445074052 references a table that doesn't
    # exist after a warm restart. Use compose down+up per-profile instead.
    subprocess.run(
        ["docker", "compose", "--profile", version, "down", "-v", "--remove-orphans"],
        cwd=str(HERE), check=False, capture_output=True,
        env={**os.environ, "PCB_FLAG": FLAG},
    )
    subprocess.run(["docker", "rm", "-f", f"pcb-n8n-{version}"],
                   check=False, capture_output=True)
    subprocess.run(
        ["docker", "compose", "--profile", version, "up", "-d", "--wait",
         "--wait-timeout", str(timeout)],
        cwd=str(HERE), check=False, capture_output=True,
        env={**os.environ, "PCB_FLAG": FLAG},
    )
    return u.wait_ready(version, timeout=timeout)


def _clear_hits() -> None:
    try:
        requests.get("http://127.0.0.1:57599/clear", timeout=5)  # noqa: S113
    except Exception:
        pass
    # fall back to clearing the bind-mounted log too
    open(HITS_FILE, "w").close()


def _run_edge(probe, version: str, restart: bool = True) -> dict:
    if restart:
        if not _restart(version):
            return {"ok": False, "error": "env not ready after restart"}
    else:
        import n8n_util as _u
        if not _u.wait_ready(version, timeout=120):
            return {"ok": False, "error": "env not ready"}
    try:
        res = probe(version=version)
    except Exception as e:  # noqa: BLE001
        res = {"ok": False, "error": f"probe raised: {e}"}
    return res


def gate(restart: bool = True) -> dict:
    _clear_hits()
    s0 = _run_edge(original_poc, "v0", restart=restart)
    _clear_hits()
    s1 = _run_edge(original_poc, "v1", restart=restart)
    _clear_hits()
    r1 = _run_edge(bypass_poc, "v1", restart=restart)
    _clear_hits()
    r2 = _run_edge(bypass_poc, "v2", restart=restart)
    result = {
        "seed_open_on_v0": s0.get("ok", False),
        "seed_closed_on_v1": not s1.get("ok", False),
        "residual_reaches_flag_on_v1": r1.get("ok", False),
        "residual_blocked_on_v2": not r2.get("ok", False),
        "seed_v0_status": s0.get("status"),
        "seed_v1_status": s1.get("status"),
        "residual_v1_status": r1.get("status"),
        "residual_v2_status": r2.get("status"),
        "seed_v0_hits": s0.get("hits"),
        "seed_v1_hits": s1.get("hits"),
        "residual_v1_hits": r1.get("hits"),
        "residual_v2_hits": r2.get("hits"),
        "seed_v0_text": s0.get("text"),
        "seed_v1_text": s1.get("text"),
        "residual_v1_text": r1.get("text"),
        "residual_v2_text": r2.get("text"),
        "passed": all([
            s0.get("ok", False),
            not s1.get("ok", False),
            r1.get("ok", False),
            not r2.get("ok", False),
        ]),
    }
    return result


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def run_gate(keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
    env = {"PCB_FLAG": FLAG}
    all_profiles = ["--profile", "v0", "--profile", "v1", "--profile", "v2"]
    _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    for cn in ("pcb-n8n-v0", "pcb-n8n-v1", "pcb-n8n-v2"):
        subprocess.run(["docker", "rm", "-f", cn], check=False, capture_output=True)
    # _restart() in gate() does fresh compose down/up per edge, so no initial compose up needed.
    result = gate()
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    elif a.gate:
        print(json.dumps(gate(restart=False), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
