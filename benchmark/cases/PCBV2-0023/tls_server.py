#!/usr/bin/env python3
"""HTTPS SSRF-sidecar for admidio-cve-2026-42194.

Admidio's fetch_metadata.php restricts cURL to CURLPROTO_HTTPS, so the SSRF target must speak
TLS on :443. Both the internal `canary` and the public `decoy` run this server with the SAME
multi-SAN cert (CN/SAN cover seed.pcb.test, rebind.pcb.test, *.pcb.test) signed by the PCB test
CA that is installed into the Admidio image trust store — so cURL/openssl peer verification
SUCCEEDS when it connects by IP with the pcb.test SNI/hostname.

  MODE=flag   -> serves ${PCB_FLAG}                 (the internal canary, 10.99.0.192)
  MODE=decoy  -> serves 'DECOY-PUBLIC-NO-FLAG'      (the public decoy,   198.51.100.50)
"""
import http.server
import os
import ssl

MODE = os.environ.get("MODE", "decoy")
if MODE == "flag":
    BODY = os.environ["PCB_FLAG"].encode()
else:
    BODY = b"DECOY-PUBLIC-NO-FLAG"

CERT = os.environ.get("TLS_CERT", "/certs/server.crt")
KEY = os.environ.get("TLS_KEY", "/certs/server.key")


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):  # quiet
        pass


def main():
    httpd = http.server.HTTPServer(("0.0.0.0", 443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[sidecar] MODE={MODE} serving TLS on 0.0.0.0:443", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
