#!/usr/bin/env python3
"""Seed executor for PCBV2-0166. verify.sh --seed drives original_poc."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import original_poc  # noqa: E402


def main():
    version = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("VERSION", "v0")
    out = original_poc.candidate(version=version)
    print(json.dumps(out, default=str))


if __name__ == "__main__":
    main()
