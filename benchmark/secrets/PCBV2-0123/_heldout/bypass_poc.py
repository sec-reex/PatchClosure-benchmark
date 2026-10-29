#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-47164 residual exploit — is_in_or_equal symlink bypass.

The CVE-2023-51449 fix (V1 = gradio 4.11.0) only hardened the containment guard
against a LITERAL `..` in the relative path (`".." in str(path.relative_to(allowed))`).
But the SAME sink still calls gradio.utils.abspath(), whose docstring states it
"does not resolve symlinks" and which, for an ALREADY-ABSOLUTE input, returns the
path completely un-normalized. So a path that traverses a symlink living inside
the allowed directory produces a relative path with NO `..` in it (e.g.
`escape/flag`), passes is_in_or_equal, and FileResponse then follows the symlink
to a file OUTSIDE the allowed dir. This is exactly CVE-2024-47164: "is_in_or_equal
may be bypassed ... ensure that all file paths are properly resolved and absolute."

Here `/gradio_tmp/escape` is a symlink -> `/` inside the allowed dir, so
`/gradio_tmp/escape/flag` resolves to `/flag` (the planted canary).

Contract: reaches the flag on V1 (gradio 4.11.0) => legitimate incomplete-fix
positive on the SAME is_in_or_equal sink. CLOSED on V2 (gradio 5.0.0), whose
CVE-2024-47164 fix adds `.resolve()` (`abspath(p).resolve()`), collapsing the
symlink so relative_to() raises ValueError -> containment holds.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# escape -> / (symlink inside the allowed dir); escape/flag resolves to /flag.
PATH = "/file=/gradio_tmp/escape/flag"


def candidate() -> dict:
    return {"probe_id": "cve-2024-47164-symlink-bypass", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
