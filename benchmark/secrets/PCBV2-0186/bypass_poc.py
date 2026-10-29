#!/usr/bin/env python3
"""[HELD-OUT] CVE-2023-37582 residual exploit -- nameserver configStorePath write.

The CVE-2023-33246 fix in RocketMQ 5.1.1 added a blocklist to the nameserver's
UPDATE_NAMESRV_CONFIG handler that blocks 'kvConfigPath' and 'configStorePathName'.
However, the actual dangerous property is 'configStorePath' (not
'configStorePathName') -- a typo/wrong-name in the blocklist. Setting
configStorePath redirects where NamesrvConfig.persist() writes, allowing
arbitrary file write.

Contract:
  V1 (5.1.1): configStorePath NOT in blocklist -> config written to controlled path -> REACHES
  V2 (5.1.2): configStorePath IS in blocklist -> update rejected -> BLOCKED

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

MARKER_PATH = "/tmp/pcb_marker.txt"


def candidate() -> dict:
    """Return the probe descriptor for this residual bypass."""
    return {
        "probe_id": "cve-2023-37582-configStorePath-write",
        "mechanism": "UPDATE_NAMESRV_CONFIG",
        "property": "configStorePath",
        "marker_path": MARKER_PATH,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
