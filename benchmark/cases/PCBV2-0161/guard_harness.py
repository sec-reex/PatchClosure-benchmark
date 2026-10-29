# -*- coding: utf-8 -*-
"""Faithful driver for the CVE-2014-9493 -> CVE-2015-1195 guard.

Loads the REAL glance/common/store_utils.py at a specific commit (mounted at
STORE_UTILS_PATH) and runs its validate_external_location() guard against a
candidate image-location URI, then, if the guard allows it, performs the REAL
disclosure via glance_store's filesystem backend (get_from_backend), exactly as
Glance's location validation / image download would.

Only the guard file is version-specific. glance_store is the genuine library.
The heavy, guard-irrelevant sibling imports of store_utils.py (glance.db, etc.)
are satisfied by inert stubs -- validate_external_location never touches them.
No glance code is modified.
"""
import os
import sys
import types
import importlib

# --- real glance_store, configured with the filesystem store ---
from oslo_config import cfg
import glance_store
from glance_store import backend

STORE_UTILS_PATH = os.environ.get("STORE_UTILS_PATH", "/app/store_utils.py")
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


def _install_stubs():
    """Inject inert stand-ins so the real store_utils.py imports cleanly without
    dragging glance's DB/wsme/crypto stack. The guard function uses none of them."""
    # oslo.config (old dotted namespace) -> real oslo_config
    import oslo_config
    import oslo_config.cfg  # noqa
    oslo_pkg = sys.modules.get("oslo") or types.ModuleType("oslo")
    oslo_pkg.__path__ = []
    sys.modules["oslo"] = oslo_pkg
    sys.modules["oslo.config"] = oslo_config
    sys.modules["oslo.config.cfg"] = oslo_config.cfg

    def _mod(name, pkg=False):
        m = types.ModuleType(name)
        if pkg:
            m.__path__ = []
        sys.modules[name] = m
        # attach as attribute on parent package so `from parent import child` works
        if "." in name:
            parent, child = name.rsplit(".", 1)
            setattr(sys.modules[parent], child, m)
        return m

    # glance package tree stubs (guard-irrelevant)
    _mod("glance", pkg=True)
    _mod("glance.common", pkg=True)
    _mod("glance.common.utils")
    _mod("glance.db")
    _mod("glance.scrubber")
    _mod("glance.openstack", pkg=True)
    _mod("glance.openstack.common", pkg=True)
    logmod = _mod("glance.openstack.common.log")
    import logging as _logging
    logmod.getLogger = _logging.getLogger
    # i18n: provide _, _LE, _LW, _LI passthroughs
    i18n = _mod("glance.i18n")
    passthru = lambda s, *a, **k: s
    for n in ("_", "_LE", "_LW", "_LI"):
        setattr(i18n, n, passthru)


def load_store_utils():
    _install_stubs()
    path = os.environ.get("STORE_UTILS_PATH", STORE_UTILS_PATH)
    spec = importlib.util.spec_from_file_location("_real_store_utils", path) \
        if hasattr(importlib, "util") else None
    if spec is not None:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    # py2.7 fallback
    import imp
    return imp.load_source("_real_store_utils", path)


def guard_allows(store_utils, uri):
    """Apply the REAL patched guard. Pre-9493 store_utils has no such function,
    which faithfully reflects V0's absence of any scheme restriction (allow)."""
    fn = getattr(store_utils, "validate_external_location", None)
    if fn is None:
        return True  # V0: no guard existed
    return bool(fn(uri))


def disclose(uri):
    """Real read-exfil via glance_store filesystem backend (same sink Glance uses)."""
    data, size = backend.get_from_backend(uri, context=None)
    return b"".join([chunk for chunk in data])


def attempt(scheme, path):
    """Full pipeline for one candidate location: build URI, run guard, then read."""
    store_utils = load_store_utils()
    uri = "%s://%s" % (scheme, path)
    if not guard_allows(store_utils, uri):
        return {"uri": uri, "allowed": False, "body": "BLOCKED_BY_GUARD"}
    try:
        body = disclose(uri)
    except Exception as e:  # pragma: no cover
        return {"uri": uri, "allowed": True, "body": "READ_ERROR:%r" % (e,)}
    try:
        body = body.decode("utf-8", "replace")
    except Exception:
        pass
    return {"uri": uri, "allowed": True, "body": body}
