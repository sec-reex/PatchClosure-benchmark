#!/usr/bin/env python3
"""Method-side executable probe (ROUND6 wrapper).
Usage: python3 seed_exec.py <candidate.json> [version]
Runs the seed entrypoint; the v1 base URL is auto-derived from the
docker-compose v1 profile if not provided."""
import sys, json, importlib.util, os, re, subprocess, glob
# seed 模块解析顺序：同目录 seed.py（staged 场景）→ 树内 benchmark/v2_harness/inputs/<EID>/seed.py
# （原实现硬编码旧工作区 legacyproj/legacynotes 的绝对路径，该工作区已不存在 → 必然 FileNotFoundError）
def _resolve_seed():
    here = os.path.dirname(os.path.abspath(__file__))
    for _d in (here, os.path.dirname(here)):        # poc/ 与 case 根（helper 模块所在）
        if os.path.isdir(_d) and _d not in sys.path:
            sys.path.insert(0, _d)
    cands = [os.path.join(here, 'seed.py')]
    d = here
    for _ in range(6):
        cands.append(os.path.join(d, 'v2_harness', 'inputs', 'PCBV2-0059', 'seed.py'))
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    for c in cands:
        if os.path.exists(c):
            _sd = os.path.dirname(c)
            if _sd not in sys.path:
                sys.path.insert(0, _sd)   # seed.py 的兄弟 helper 模块（如 pgadm_util）
            return c
    raise SystemExit('seed module not found; tried: ' + ', '.join(cands))


_SP = _resolve_seed()
spec = importlib.util.spec_from_file_location('_seedmod', _SP)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def _v1_base():
    return 'http://127.0.0.1:26907'


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    base = cand.get('_base') or os.environ.get('PCB_BASE') or _v1_base()
    out = None
    if hasattr(mod, 'candidate'):
        out = mod.candidate(version=version, flag='pcbflag')
    elif hasattr(mod, 'run') and base:
        out = mod.run(base)
    elif hasattr(mod, 'original_poc'):
        out = mod.original_poc(version=version)
    else:
        out = {'ok': False, 'status': 0, 'body': 'no seed entrypoint'}
    if isinstance(out, dict) and 'status' in out:
        print(json.dumps({'ok': out.get('ok', False), 'status': out.get('status'), 'body': str(out.get('body', ''))[:400]}, default=str))
    else:
        print(json.dumps(out, default=str))