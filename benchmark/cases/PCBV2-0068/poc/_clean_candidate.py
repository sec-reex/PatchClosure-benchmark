#!/usr/bin/env python3
# auto-generated candidate cleaner: strip quotes + replace PCBFLAG_* placeholder
import json, re, sys
s = sys.argv[1]
flag = sys.argv[2]

def clean(x):
    x = x.strip().strip(chr(34)).strip(chr(39))
    x = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, x)
    return x

try:
    d = json.loads(s)
    if isinstance(d, dict):
        d = {k: (clean(v) if isinstance(v, str) else v) for k, v in d.items()}
    print(json.dumps(d))
except Exception:
    print(json.dumps({'path': clean(s), 'to': clean(s), 'payload': clean(s), 'css': clean(s)}))
