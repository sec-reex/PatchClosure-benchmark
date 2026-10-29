#!/usr/bin/env python3
"""[GIVEN] CVE-2023-44400 seed exploit — old-token replay on a NEW connection after a
password change, over a REAL Uptime Kuma socket.io connection.

Before v1.23.3, Uptime Kuma's JWT was `jwt.sign({ username }, secret)` — bound to nothing but
the username — and the `loginByToken` handler never checked whether the password had changed. So
a token captured from an earlier login stays valid forever: an attacker opens a FRESH socket
connection, replays the old token via `loginByToken`, and is re-authenticated even though the
victim has since changed their password, then reads the private ${PCB_FLAG} monitor via the real
authenticated `getMonitorList` event.

This module is a pure candidate DESCRIPTOR (mode='seed'); it contains NO Uptime Kuma code.
"""
from __future__ import annotations

import json
import secrets


def candidate() -> dict:
    return {
        "probe_id": "cve-2023-44400-new-conn-old-token-replay",
        "mode": "seed",
        "nonce": secrets.token_hex(3),
    }


if __name__ == "__main__":
    print(json.dumps(candidate()))
