#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-27152 residual for the axios baseURL destination-control SSRF guard.

The CVE-2024-39338 fix (axios@1.7.4) only closed the PROTOCOL-RELATIVE `//host` form (by making the
http adapter's `new URL(fullPath, undefined)` throw). The SAME sink still admits a FULLY-ABSOLUTE URL:
`http://internal-sidecar/flag` is isAbsoluteURL=true, so buildFullPath returns it untouched and
`new URL('http://internal-sidecar/flag')` is a valid URL -> baseURL='http://public-app' is still
OVERRIDDEN and the request reaches the INTERNAL-only sidecar, retrieving ${PCB_FLAG}. This is the
GHSA-jr5f-v2jv-69x6 / CVE-2025-27152 "absolute URL overrides baseURL" residual: an incomplete-fix
bypass of the CVE-2024-39338 guard. V2 (axios@1.8.2) adds the allowAbsoluteUrls parameter to
buildFullPath; with allowAbsoluteUrls:false the absolute path is combineURLs()'d onto baseURL
(-> host public-app) and the destination stays pinned -> BLOCKED.
"""


def candidate():
    return {"path": "http://internal-sidecar/flag", "probe_id": "residual-cve-2025-27152-absolute-url"}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
