# -*- coding: utf-8 -*-
"""Thin HTTP consumer over the installed OpenStack Glance package.

GET /read?scheme=<file|filesystem|...>&path=<abs-path>
  Builds "<scheme>://<path>", runs the real
  glance.common.store_utils.validate_external_location from the
  pip-installed glance tree, and (if allowed) discloses the file via
  glance_store's filesystem backend.

GET /healthz -> {"status":"ok"} plus the installed glance module paths.

Kilo Glance imports `oslo.config` / `oslo.i18n` / `oslo.utils`; the
installed oslo_* packages expose the underscored names. The alias below
is a namespace compatibility shim for Oslo, not a Glance stub.
"""
import json
import os
import sys

import sitecustomize  # Oslo oslo.* -> oslo_* alias (not a Glance stub)

import glance
from glance.common import store_utils
import glance_store
from glance_store import backend
from oslo_config import cfg
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from urlparse import urlparse, parse_qs

assert "site-packages" in (store_utils.__file__ or ""), store_utils.__file__

VERSION = os.environ.get("PCB_VERSION", "v?")
DATADIR = os.environ.get("GLANCE_DATADIR", "/var/lib/glance/images")


def configure_store():
    CONF = cfg.CONF
    backend.register_opts(CONF)
    if not os.path.exists(DATADIR):
        os.makedirs(DATADIR)
    CONF.set_override("stores", ["file", "http"], group="glance_store")
    CONF.set_override("default_store", "file", group="glance_store")
    CONF.set_override("filesystem_store_datadir", DATADIR, group="glance_store")
    backend.create_stores(CONF)
    return CONF


configure_store()


def attempt(scheme, path):
    uri = "%s://%s" % (scheme, path)
    fn = getattr(store_utils, "validate_external_location", None)
    if fn is None:
        allowed = True
    else:
        allowed = bool(fn(uri))
    if not allowed:
        return {
            "uri": uri,
            "allowed": False,
            "body": "BLOCKED_BY_GUARD",
            "store_utils": store_utils.__file__,
        }
    try:
        data, _size = backend.get_from_backend(uri, context=None)
        body = b"".join([chunk for chunk in data])
    except Exception as e:
        return {
            "uri": uri,
            "allowed": True,
            "body": "READ_ERROR:%r" % (e,),
            "store_utils": store_utils.__file__,
        }
    try:
        body = body.decode("utf-8", "replace")
    except Exception:
        pass
    return {
        "uri": uri,
        "allowed": True,
        "body": body,
        "store_utils": store_utils.__file__,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":
            self._send(200, {
                "status": "ok",
                "version": VERSION,
                "glance": getattr(glance, "__file__", None),
                "store_utils": store_utils.__file__,
                "glance_store": getattr(glance_store, "__file__", None),
            })
            return
        if u.path == "/read":
            q = parse_qs(u.query)
            scheme = (q.get("scheme") or ["file"])[0]
            path = (q.get("path") or ["/canary/secret.txt"])[0]
            res = attempt(scheme, path)
            res["version"] = VERSION
            self._send(200, res)
            return
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    Server(("0.0.0.0", port), Handler).serve_forever()
