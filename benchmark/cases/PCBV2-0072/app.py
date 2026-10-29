#!/usr/bin/env python3
"""Real-library-wrap SSRF wrapper for pydantic-ai-cve-2026-46678 (CVE-2026-25580 -> CVE-2026-46678).

This is a MINIMAL real HTTP service that drives the REAL, pip-INSTALLED `pydantic_ai`
media-download code path. Nothing about pydantic-ai's SSRF guard is reimplemented or lifted here:
the guard runs entirely from the installed package's own bytes.

    GET /fetch?url=<target>&allow_local=<0|1>

builds a real `pydantic_ai.messages.ImageUrl` (a `FileUrl`, exactly the object an agent tool-run
carries in its message history when a model returns a media URL) and calls the REAL
`pydantic_ai.models.download_item(item, data_format='text')`. In pydantic-ai >= 1.56.0 that function
internally calls `pydantic_ai._ssrf.safe_download(item.url, allow_local=...)` — the CVE-2026-25580
SSRF guard. We echo back the downloaded body (the observable); the flag appears only if the
installed version's guard allowed the URL and the ensuing real httpx fetch reached the metadata canary.

Version behaviour is decided ENTIRELY by which real pydantic-ai wheel is installed in the image:
  PYDANTIC_AI_VER=1.55.0  V0  download_item -> raw client.get, no _ssrf.py  (CVE-2026-25580 vuln)
  PYDANTIC_AI_VER=1.56.0  V1  download_item -> safe_download; _CLOUD_METADATA_IPS is a plain STRING
                              frozenset with no IPv6-transition normalization   -> CVE-2026-46678 target
  PYDANTIC_AI_VER=1.99.0  V2  download_item -> safe_download; _normalize_ip() unwraps
                              IPv4-mapped/6to4/NAT64 before the blocklist check -> residual closed

`allow_local` maps to the real FileUrl API: force_download='allow-local' (allow_local=True) vs
force_download=True (allow_local=False). On V0 (1.55.0) force_download is ignored by download_item.
"""
from __future__ import annotations

import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# REAL installed pydantic-ai package (from PyPI, pinned per image). No lift, no stub.
import pydantic_ai
from pydantic_ai.messages import ImageUrl
from pydantic_ai.models import download_item

VER = os.environ.get("HARNESS_VER", "v1")
PKG_VER = getattr(pydantic_ai, "__version__", "unknown")


def _body_of(downloaded) -> str:
    # download_item returns a DownloadedItem (TypedDict in current releases; guard for objects too).
    if isinstance(downloaded, dict):
        return downloaded.get("data")
    return getattr(downloaded, "data", None)


def _make_item(url: str, allow_local: bool) -> ImageUrl:
    """Build the real FileUrl the same way an agent tool-run would.

    allow_local=True maps to force_download='allow-local' (the CVE-2026-46678 precondition). On
    pre-1.56.0 pydantic-ai (V0) force_download is a strict bool field that predates the
    'allow-local' literal AND there is no SSRF guard at all, so the value is behaviourally
    irrelevant there — fall back to a plain bool so the real ImageUrl still constructs."""
    try:
        return ImageUrl(url=url, force_download=("allow-local" if allow_local else True))
    except Exception:  # noqa: BLE001  (older bool-only force_download field)
        return ImageUrl(url=url, force_download=True)


async def _download(url: str, allow_local: bool) -> str:
    """Drive the REAL pydantic-ai download sink and return the fetched body text."""
    item = _make_item(url, allow_local)
    downloaded = await download_item(item, data_format="text")
    return _body_of(downloaded)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, obj: dict):
        blob = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/":
            self._send(200, {"ok": True, "version": VER, "pydantic_ai": PKG_VER})
            return
        if p.path != "/fetch":
            self._send(404, {"error": "not found"})
            return
        q = parse_qs(p.query)
        url = (q.get("url") or [""])[0]
        allow_local = (q.get("allow_local") or ["0"])[0] in ("1", "true", "True")
        result = {"version": VER, "pydantic_ai": PKG_VER, "target_url": url,
                  "allow_local": allow_local, "ok": False, "body": None, "error": None}
        try:
            body = asyncio.run(_download(url, allow_local))
            result.update(ok=True, body=body)
        except Exception as e:  # noqa: BLE001  (real guard raises ValueError; fetch may raise httpx errors)
            result["error"] = f"{type(e).__name__}: {e}"
        self._send(200, result)


if __name__ == "__main__":
    port = int(os.environ.get("HARNESS_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
