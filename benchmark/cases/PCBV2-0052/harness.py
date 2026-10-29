#!/usr/bin/env python3
"""Faithful-core harness for the aiohttp pure-Python HTTP parser Content-Length
guard (CVE-2023-47627 -> CVE-2024-23829, CWE-444 HTTP request smuggling).

This image runs a REAL, unmodified aiohttp.web server whose request parser is the
PURE-PYTHON one (AIOHTTP_NO_EXTENSIONS=1 forces the Python HttpRequestParser instead
of the C llhttp parser -- exactly the parser BOTH CVEs patch and the only one the
advisories cover). Two routes:

    GET/POST /      -> "ok"                (a normal front request)
    GET      /flag  -> ${PCB_FLAG}         (the internal canary the smuggle targets)

The oracle sends RAW crafted bytes over a socket: an obfuscated-Content-Length first
request followed by a pipelined `GET /flag` "smuggled" request. Whether the smuggled
request is processed is decided ENTIRELY by whether this aiohttp version accepts the
malformed Content-Length:

  * accepted  -> first request framed with an empty body, the pipelined `GET /flag`
                 is parsed as the next request on the keep-alive connection -> FLAG.
  * rejected  -> aiohttp answers 400 and closes the connection before the pipelined
                 request is ever parsed -> NO FLAG.

Nothing in aiohttp is modified; the version's own parser is the guard.

  AIOHTTP_VER=3.8.5  -> pre-fix: get_content_length uses `int(length_hdr)` which
        accepts `+0` / `1_0` / Unicode digits.                          [V0 seed env]
  AIOHTTP_VER=3.8.6  -> CVE-2023-47627 fix: `length_hdr.strip(" \\t").isdecimal()`
        rejects `+0`/underscores, but `.isdecimal()` STILL accepts Unicode decimal
        digits (e.g. Arabic-Indic U+0660) -> incomplete.        [V1 TARGET, GIVEN]
  AIOHTTP_VER=3.9.2  -> CVE-2024-23829 fix: `DIGITS.fullmatch(length_hdr)` with
        DIGITS = re.compile(r"\\d+", re.ASCII) -> Unicode digits rejected. [V2 negative]
"""
import os

# Force the pure-Python HTTP parser BEFORE importing aiohttp (advisory-mandated path).
os.environ["AIOHTTP_NO_EXTENSIONS"] = "1"

import aiohttp  # noqa: E402
from aiohttp import http_parser, web  # noqa: E402

FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_unset")
APP_PORT = int(os.environ.get("APP_PORT", "8080"))
VER = os.environ.get("AIOHTTP_VER", "?")


async def root(request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def flag(request: web.Request) -> web.Response:
    # Internal canary: only reached when a smuggled request is parsed on this connection.
    return web.Response(text=FLAG)


def main() -> None:
    app = web.Application()
    app.router.add_route("*", "/", root)
    app.router.add_get("/flag", flag)
    parser_mod = getattr(http_parser.HttpRequestParser, "__module__", "?")
    print(
        "[harness ver=%s aiohttp=%s] parser=%s (python-parser=%s) on 0.0.0.0:%d"
        % (VER, aiohttp.__version__, parser_mod, "_http_parser" not in parser_mod, APP_PORT),
        flush=True,
    )
    web.run_app(app, host="0.0.0.0", port=APP_PORT, print=None)


if __name__ == "__main__":
    main()
