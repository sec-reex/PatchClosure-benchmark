#!/bin/sh
# GATE_DRIVER for PCBV2-0152 (Next.js CVE-2026-45109, middleware auth bypass).
# 4 services across profiles: v0 (webpack 15.2.0), v1_web (webpack 15.5.16),
# v1_turbo (turbopack 15.5.16), v2_turbo (turbopack 15.5.18).
# Same bypass paths, different versions. gate.sh deploys externally.
set -u

python3 -c "
import sys, os, json
sys.path.insert(0, '.')
sys.path.insert(0, 'poc')
sys.path.insert(0, '_heldout')

import oracle

FLAG = os.environ.get('PCB_FLAG', '')

PORTS = {
    'v0':       int(os.environ.get('PORT_V0_0', '41090')),
    'v1_web':   int(os.environ.get('PORT_V1_WEB_0', '41091')),
    'v1_turbo': int(os.environ.get('PORT_V1_TURBO_0', '41092')),
    'v2_turbo': int(os.environ.get('PORT_V2_TURBO_0', '41093')),
}

def test_edge(label, port):
    base = f'http://127.0.0.1:{port}'
    result = oracle.probe(base, FLAG)
    leaked = result.get('flag_leaked', False)
    print(f'  {label}: port={port} leaked={leaked}', file=sys.stderr)
    return leaked

edges = {}
# Edge 1: original bypass on v0 (seed reaches)
edges['seed_v0_reaches'] = test_edge('seed@v0', PORTS['v0'])

# Edge 2: original bypass on v1_web (seed blocked by webpack fix)
edges['seed_v1_blocked'] = not test_edge('seed@v1_web', PORTS['v1_web'])

# Edge 3: same bypass on v1_turbo (residual reaches — turbopack path unfixed)
edges['residual_v1_reaches'] = test_edge('residual@v1_turbo', PORTS['v1_turbo'])

# Edge 4: same bypass on v2_turbo (residual blocked by turbopack fix)
edges['residual_v2_blocked'] = not test_edge('residual@v2_turbo', PORTS['v2_turbo'])

passed = all(edges.values())
json.dump({**edges, 'passed': passed}, sys.stdout, indent=2)
print()
"
