#!/usr/bin/env python3
"""[GIVEN] CVE-2023-6029 seed — EazyDocs missing-authorization document deletion.

The plugin's `Delete_Post::delete_doc()` runs on `admin_init` (fires on any /wp-admin/
request, so a low-priv subscriber reaches it). The `?Doc_Delete=yes&DeleteID=<id>` branch
force-trashes ANY post id via wp_trash_post() with NO authorization check.

Seed technique (the raw CVE-2023-6029 request): a bare Doc_Delete with NO nonce.
  V0 (EazyDocs 2.3.5): no nonce check, no capability check -> the admin's victim document
      is trashed cross-privilege -> canary releases the flag.  REACHES.
  V1 (EazyDocs 2.3.9): the fix added wp_verify_nonce(_wpnonce, DeleteID); a request with no
      _wpnonce fails verification -> nothing trashed.  BLOCKED (no flag).

The residual (CVE-2024-0248) reaches the SAME flag on V1 by supplying a VALID nonce that the
2.3.9 build leaks to any authenticated user (same Doc_Delete sink, same victim doc, same flag
channel — a pure nonce-encoding bypass of the guard the fix added).
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate for the CVE-2023-6029 seed: Doc_Delete with no nonce."""
    return {
        "probe_id": "cve-2023-6029-doc_delete-no-nonce",
        "technique": "no-nonce",       # bare Doc_Delete, no _wpnonce (raw -6029 request)
        "sink": "Doc_Delete",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
