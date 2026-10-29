#!/bin/sh
# Generic GATE_DRIVER for ReDoS/latency oracles (0008, 0110, 0183, 0184).
# Maps non-standard latency keys to canonical 4-edge names.
set -u
TMPOUT=$(mktemp /tmp/pcb_redos_XXXXXX)
python3 oracle.py > "$TMPOUT" 2>&1
RC=$?

python3 -c "
import json, sys
with open('$TMPOUT') as f:
    text = f.read()
idx = text.find('=== GATE REPORT ===')
if idx < 0:
    # dump tail of oracle output for debugging
    tail = text[-2000:] if len(text) > 2000 else text
    json.dump({'error': 'no gate report', 'passed': False,
               'oracle_rc': $RC, 'oracle_tail': tail}, sys.stdout, indent=2)
    sys.exit(0)
report = json.loads(text[idx + 19:].strip())
b = report.get('booleans', {})
edges = {
    'seed_v0_reaches':     b.get('original_slow_on_v0', False),
    'seed_v1_blocked':     b.get('original_bounded_on_v1', False),
    'residual_v1_reaches': b.get('residual_slow_on_v1', False),
    'residual_v2_blocked': b.get('residual_bounded_on_v2',
                                 b.get('residual_v1_over_v2_gt_50x', False)),
}
passed = b.get('passed', all(edges.values()))
json.dump({**edges, 'passed': passed}, sys.stdout, indent=2)
print()
"
rm -f "$TMPOUT"
