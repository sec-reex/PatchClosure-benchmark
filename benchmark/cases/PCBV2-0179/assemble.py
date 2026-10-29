#!/usr/bin/env python3
"""Build-time shim assembler (recipe model — NOTHING vendored in the case dir).

At `docker build`, the REAL pyLoad source files for this version's pinned commit
are fetched (via Dockerfile `ADD`) into /src:
    /src/fs.py     = src/pyload/core/utils/fs.py     @ SHA
    /src/purge.py  = src/pyload/core/utils/purge.py  @ SHA
    /src/UnTar.py  = src/pyload/plugins/extractors/UnTar.py @ SHA

This script assembles a minimal importable `pyload` package under /app whose
SECURITY-RELEVANT code is the REAL code, verbatim, extracted from those files:
  - fs.is_within_directory / fs.safejoin / fs.safepath / fs.safename  (real, ast-sliced)
  - purge.chars / purge.truncate                                      (real, ast-sliced)
  - plugins/extractors/UnTar.py                                       (real, copied verbatim)
Only inert framework glue is stubbed: pyload.plugins.base.extractor
(ArchiveError / CRCError / BaseExtractor are just exception/base classes that
`_safe_extractall` references but whose bodies are irrelevant to the traversal
check). This keeps the differential faithful (the V1->V2 delta lives ENTIRELY in
the real UnTar._safe_extractall + real fs.is_within_directory) while avoiding the
full pyLoad dependency tree.
"""
import ast
import os
import pathlib

SRC = pathlib.Path("/src")
APP = pathlib.Path("/app")


def slice_funcs(src_path, wanted):
    """Return source text of the wanted top-level functions that exist in src_path."""
    text = src_path.read_text()
    tree = ast.parse(text)
    out = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            out.append(ast.get_source_segment(text, node))
    return "\n\n\n".join(out)


def write(path, content):
    p = APP / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def main():
    # package skeleton
    for pkg in ["pyload", "pyload/core", "pyload/core/utils",
                "pyload/plugins", "pyload/plugins/base", "pyload/plugins/extractors"]:
        write(pkg + "/__init__.py", "")

    # real purge.chars / purge.truncate (uses re only)
    purge_body = slice_funcs(SRC / "purge.py", {"chars", "truncate"})
    write("pyload/core/utils/purge.py", "import re\n\n\n" + purge_body + "\n")

    # real fs guard functions (uses os + purge only)
    fs_body = slice_funcs(SRC / "fs.py",
                          {"is_within_directory", "safepath", "safejoin", "safename"})
    write("pyload/core/utils/fs.py", "import os\n\nfrom . import purge\n\n\n" + fs_body + "\n")

    # inert stub for the extractor base (bodies irrelevant to the traversal check)
    write("pyload/plugins/base/extractor.py",
          "class ArchiveError(Exception):\n    pass\n\n\n"
          "class CRCError(Exception):\n    pass\n\n\n"
          "class PasswordError(Exception):\n    pass\n\n\n"
          "class BaseExtractor:\n    pass\n")

    # REAL UnTar.py, verbatim
    write("pyload/plugins/extractors/UnTar.py", (SRC / "UnTar.py").read_text())

    # sanity: the real _safe_extractall must import
    import sys
    sys.path.insert(0, str(APP))
    from pyload.plugins.extractors.UnTar import _safe_extractall  # noqa
    print("assemble.py OK: real _safe_extractall imported for this version")


if __name__ == "__main__":
    main()
