import json, sys, subprocess, time, urllib.parse
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from flag_oracle import new_flag
sys.path.insert(0, str(HERE))
import oracle

BASE = "http://127.0.0.1:39114"
FLAG = "PCBFLAG_e461ad58e6b3"

# Register admin
oracle._register(BASE, "pcbadmin", oracle.ADMIN["email"], oracle.ADMIN["password"])
token = oracle._login(BASE, oracle.ADMIN["email"], oracle.ADMIN["password"])
print("admin token len:", len(token))

# Check if pcb_canary exists already
if token:
    r = oracle._get_json(f"{BASE}/api/pcb_canary", token)
    print("pcb_canary query:", json.dumps(r)[:300])

    # Register attacker too
    oracle._register(BASE, "attacker", oracle.ATTACKER["email"], oracle.ATTACKER["password"])
    atoken = oracle._login(BASE, oracle.ATTACKER["email"], oracle.ATTACKER["password"])
    print("attacker token len:", len(atoken))
    ar = oracle._get_json(f"{BASE}/api/pcb_canary", atoken)
    print("attacker pcb_canary query:", json.dumps(ar)[:300])
