#!/usr/bin/env python3
"""REAL Python HTTP service for deser_keras_safe_mode (CVE-2025-1550 -> CVE-2025-8747).

This mirrors a real ML web service that loads a user-uploaded Keras v3 model/config.
An EXTERNAL client POSTs an attacker-supplied Keras architecture config (application/json)
to ``POST /load``; the service packs it into a minimal ``.keras`` archive alongside a
version-matched, weightless ``model.weights.h5`` (baked at image build) and runs the REAL,
unmodified published Keras safe-mode deserialization path:

    keras.saving.load_model(m.keras, safe_mode=True)     # per-version _retrieve_class_or_fn guard
    model(zeros((1,1)))                                  # one benign forward pass

The attacker config carries a ``Lambda`` layer whose ``function`` node names a module +
callable. During load, ``serialization_lib._retrieve_class_or_fn`` resolves that name and
``Lambda.call`` INVOKES it with attacker-controlled ``arguments`` -- even under safe_mode=True.
Whether the callable is resolved+invoked is decided ENTIRELY by that Keras version's own
unmodified allowlist. Nothing in Keras is modified.

Benign canary (rce-oob read/exfil): ${PCB_FLAG} is planted at /canary/flag.txt (outside the
model dir) at container start. The invoked in-package callable (or out-of-tree helper) copies
that file into /out with a harmless local file:// copy -- no network, no exec, no attacker data.
``/load`` returns the /out contents; the ${PCB_FLAG} token appears there iff the callable was
invoked past the guard.
"""
import os
import sys
import json
import zipfile
import shutil
import tempfile

os.environ.setdefault("KERAS_BACKEND", "jax")
# Make the out-of-tree helper module `pcb_leak` (the original CVE-2025-1550 seed target)
# importable, exactly as a real deployment's app dir would be on sys.path.
sys.path.insert(0, "/work")

from flask import Flask, request, jsonify
import keras
import numpy as np

app = Flask(__name__)

# Version-matched, weightless Input->Lambda(identity) weights baked at image build time,
# so we can pack a loadable .keras from ANY attacker config.json at request time.
with open("/work/ref_weights.h5", "rb") as _f:
    _WTS = _f.read()
_META = ('{"keras_version":"%s","date_saved":"pcb"}' % keras.__version__).encode()


@app.get("/health")
def health():
    return jsonify(ok=True, keras=keras.__version__)


@app.post("/load")
def load():
    """Deserialize an attacker-supplied Keras v3 model config via the REAL safe-mode load path."""
    cfg = request.get_json(force=True, silent=True)
    if cfg is None:
        return jsonify(error="bad-json"), 400
    cfg_text = json.dumps(cfg)

    fd, mpath = tempfile.mkstemp(suffix=".keras")
    os.close(fd)
    with zipfile.ZipFile(mpath, "w") as z:
        z.writestr("metadata.json", _META)
        z.writestr("config.json", cfg_text)
        z.writestr("model.weights.h5", _WTS)

    shutil.rmtree("/out", ignore_errors=True)
    os.makedirs("/out", exist_ok=True)

    status = {"keras": keras.__version__, "loaded": False, "forwarded": False, "error": None}
    try:
        m = keras.saving.load_model(mpath, safe_mode=True)
        status["loaded"] = True
        try:
            m(np.zeros((1, 1), dtype="float32"))
            status["forwarded"] = True
        except Exception as e:  # noqa: BLE001
            status["error"] = "forward:" + type(e).__name__ + ":" + str(e)[:180]
    except Exception as e:  # noqa: BLE001
        status["error"] = "load:" + type(e).__name__ + ":" + str(e)[:220]
    finally:
        try:
            os.remove(mpath)
        except OSError:
            pass

    leaked = ""
    for r, _, fs in os.walk("/out"):
        for x in fs:
            try:
                leaked += open(os.path.join(r, x)).read()
            except OSError:
                pass

    return jsonify(status=status, leaked=leaked.strip())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
