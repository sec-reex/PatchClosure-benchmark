import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE))
import oracle

FLAG = "PCBFLAG_e461ad58e6b3"
ok = oracle.seed_canary("v1", FLAG)
print("seed_canary v1 ok:", ok)
