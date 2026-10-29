#!/usr/bin/env python3
"""Real HTTP sink service for codeinj_pyyaml_fullloader
(CVE-2020-1747 [PyYAML FullLoader / yaml.full_load: the FullConstructor
python/object/new object-instantiation multi-constructor lets crafted YAML
poison an instance's `extend` attribute and have it invoked -> code injection
even though full_load was advertised as the safe-ish loader], fixed 5.3.1 = TARGET
-> CVE-2020-14343 [the 5.3.1 state-key blacklist is an INCOMPLETE fix: moving the
poisoned attr into the class-CONSTRUCTION map (python/object/new + tuple + map)
still reaches the escape], fixed 5.4).

A minimal REAL Flask web service that mirrors an ordinary app which accepts a
user-supplied YAML document (config upload, API body, ...) and parses it with the
REAL, unmodified PyYAML:

    data = yaml.full_load(request.data)     # <-- THE SINK (per-version FullConstructor guard)

The installed PyYAML version (build-arg PYYAML_VER, pip install PyYAML==X) is the
ONLY thing that varies across v0/v1/v2 -- the service code is identical. That is the
point: same POST /parse endpoint, same yaml.full_load call, three consecutive PyYAML
releases, and whether the object escape fires differs per version.

Read-exfil canary (benign): the container plants the per-run ${PCB_FLAG} at /flag.
The malicious YAML's object escape, when the FullConstructor instantiates it, runs a
BENIGN reader (`open('/flag').read()` copied into /out/leak.txt -- a local file
read+copy, NO shell, NO subprocess, NO network, NO persistence). /parse then reads
that leak sink back and returns it, so the flag surfaces in the HTTP RESPONSE iff
the FullLoader object escape fired during the real yaml.full_load. Nothing in PyYAML
is modified.
"""
import os
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

LEAK = "/out/leak.txt"
os.makedirs("/out", exist_ok=True)


@app.route("/parse", methods=["POST"])
def parse():
    # Clear the leak sink so a stale flag can never be mistaken for a fresh escape.
    try:
        os.remove(LEAK)
    except OSError:
        pass

    payload = request.get_data()  # raw request body = the attacker-supplied YAML document

    result = {"pyyaml": yaml.__version__, "loaded": False, "error": None,
              "result": None, "leaked": ""}
    try:
        # THE SINK: the real, unmodified PyYAML FullLoader over external request data.
        data = yaml.full_load(payload)
        result["loaded"] = True
        try:
            result["result"] = repr(data)[:160]
        except Exception as e:  # noqa: BLE001
            result["result"] = "<repr-failed:%s>" % type(e).__name__
    except Exception as e:  # noqa: BLE001
        result["error"] = type(e).__name__ + ": " + str(e)[:240]

    # Content the response is DERIVED from: if the object escape fired during the load,
    # its benign reader copied /flag into the leak sink -> surface it in the response.
    try:
        with open(LEAK) as fh:
            result["leaked"] = fh.read()
    except OSError:
        pass

    return jsonify(result)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "pyyaml": yaml.__version__,
                    "flag_planted": os.path.exists("/flag")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "80")))
