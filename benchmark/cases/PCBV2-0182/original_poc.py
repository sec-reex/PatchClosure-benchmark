#!/usr/bin/env python3
"""Shim: re-exports original_poc function and ORIGINAL_PAYLOAD for oracle import.
Platform seed entry is poc/original_poc.py (JSON candidate, san_mode=tags)."""
import importlib.util
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_poc_file = _here / "poc" / "original_poc.py"
_spec = importlib.util.spec_from_file_location("_inner_original_poc", str(_poc_file))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ORIGINAL_PAYLOAD = _mod.CDATA_STYLE_PAYLOAD


def original_poc(*, version="v0"):
    if str(_here) not in sys.path:
        sys.path.insert(0, str(_here))
    from poc_common import run_payload
    c = _mod.candidate()
    return run_payload(c["payload"], version, san_mode=c["san_mode"], visit_mode=c["mode"])


if __name__ == "__main__":
    import runpy
    runpy.run_path(str(_poc_file), run_name="__main__")
