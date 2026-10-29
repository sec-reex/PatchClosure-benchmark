#!/usr/bin/env python3
"""Seed executor for PCBV2-0165. verify.sh drives the HTTP probe itself."""
import json
import os
import sys

import original_poc


def main():
    version = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("VERSION", "v0")
    out = original_poc.candidate(version=version)
    print(json.dumps(out, default=str))


if __name__ == "__main__":
    main()
