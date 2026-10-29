#!/usr/bin/env python3
"""POST candidate template to the running Jinjava /render service."""
import json
import os
import sys
import urllib.error
import urllib.request


def http_render(port, template):
    url = f"http://127.0.0.1:{int(port)}/render"
    req = urllib.request.Request(
        url,
        data=template.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"HTTP_{e.code}: " + e.read().decode("utf-8", "replace")
    except Exception as e:
        return f"HTTP_ERROR: {e}"


def run_probe(candidate, version="v1"):
    template = candidate["template"] if isinstance(candidate, dict) else str(candidate)
    port = os.environ.get("PCB_TARGET_PORT")
    if not port:
        raise SystemExit("PCB_TARGET_PORT is required")
    return http_render(port, template)


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    body = run_probe(cand, version=version)
    print(json.dumps({"body": body}))
