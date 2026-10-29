"""BENIGN out-of-tree helper (a NON-keras top-level module) used to model the
original CVE-2025-1550 exploit primitive.

CVE-2025-1550 (the target/incomplete fix, keras 3.9.0) added a package allowlist
in serialization_lib._retrieve_class_or_fn: a Lambda-gadget `function` node may
only import a module whose top-level package is in
{keras, keras_hub, keras_cv, keras_nlp}. This module's package is `pcb_leak`,
which is OUTSIDE that set, so V1/V2 refuse to import it (the original is blocked).
On V0 (keras 3.8.0, pre-fix) there is no allowlist, so it imports + runs.

`leak` deliberately IGNORES its first positional argument (the Keras tensor the
Lambda layer passes as inputs) and simply copies the planted canary flag file to
an output path. There is NO payload: no exec, no network, no attacker data --
only a local file copy that surfaces the per-run ${PCB_FLAG} canary, proving the
attacker-named out-of-tree callable was invoked during model load+use."""


def leak(x=None, flag_path=None, out_path=None):
    with open(flag_path) as f:
        data = f.read()
    with open(out_path, "w") as f:
        f.write(data)
    return out_path
