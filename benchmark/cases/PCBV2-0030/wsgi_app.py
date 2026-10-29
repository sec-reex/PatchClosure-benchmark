"""
Tiny REAL WSGI app that exercises WebOb's real Location-header normalization.

GET /redirect?to=<user-input>  ->  Response(status=302, location=<user-input>)

WebOb makes the Location header absolute at WSGI __call__ time via
Response._abs_headerlist -> _make_location_absolute. That method is exactly
the code path patched by CVE-2024-42353 (1.8.8) and CVE-2026-44889 (1.8.10).
The emitted `Location` response header is the sole observable.

Nothing here reimplements WebOb: the redirect target normalization is done
100% by the installed `webob` package bytes (pip install WebOb==<ver>).
"""
from wsgiref.simple_server import make_server, WSGIRequestHandler
from webob import Request, Response
import importlib.metadata as _md

_WEBOB_VER = _md.version("webob")


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *a, **k):
        pass


def app(environ, start_response):
    req = Request(environ)
    if req.path == "/webob-version":
        r = Response(_WEBOB_VER, content_type="text/plain")
        return r(environ, start_response)
    if req.path == "/redirect":
        # `to` is url-decoded by WebOb's GET multidict (e.g. %09 -> real TAB).
        to = req.GET.get("to", "/")
        # REAL WebOb: the Location normalization / anti-open-redirect logic
        # lives entirely inside webob.Response and runs on __call__.
        resp = Response(status=302, location=to)
        return resp(environ, start_response)
    return Response("ok", content_type="text/plain")(environ, start_response)


if __name__ == "__main__":
    httpd = make_server("0.0.0.0", 8000, app, handler_class=_QuietHandler)
    print("webob %s serving on :8000" % _WEBOB_VER, flush=True)
    httpd.serve_forever()
