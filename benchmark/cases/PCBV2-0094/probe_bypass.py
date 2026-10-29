import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE))
import oracle

res = oracle.run_bypass_probe("v1")
print(json.dumps(res, indent=2))
expected = "PCBFLAG_e461ad58e6b3"
print("matches expected flag:", res.get("extracted") == expected)
