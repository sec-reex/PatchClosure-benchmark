import json, urllib.request, subprocess, sys

BASE="http://127.0.0.1:39821"
FEED="http://11.0.0.10/feed.xml"
EMAIL,PW="listener@pcb.test","ListenerPass123"

def http(method,url,data=None,headers=None,timeout=120):
    req=urllib.request.Request(url,data=data,method=method,headers=headers or {})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            return r.status,r.read()
    except urllib.error.HTTPError as e:
        return e.code,e.read()
    except Exception as e:
        return -1,str(e).encode()

st,body=http("POST",f"{BASE}/api/me",data=json.dumps({"email":EMAIL,"password":PW}).encode(),
             headers={"Content-Type":"application/json","Accept":"application/json"})
print("login status",st)
tok=json.loads(body)
api,audio=tok["token"],tok["audio-token"]

st,body=http("POST",f"{BASE}/api/podcasts",data=json.dumps({"url":FEED}).encode(),
             headers={"Authorization":f"Bearer {api}","Content-Type":"application/json","Accept":"application/json"})
print("subscribe status",st,"body",body[:300])
try:
    pid=json.loads(body)["id"]
except (KeyError,ValueError):
    st,body=http("GET",f"{BASE}/api/podcasts",headers={"Authorization":f"Bearer {api}","Accept":"application/json"})
    items=json.loads(body)
    items=items.get("data",items) if isinstance(items,dict) else items
    pid=next(p["id"] for p in items if p.get("url")==FEED)
print("pid",pid)

st,body=http("GET",f"{BASE}/api/podcasts/{pid}/episodes",headers={"Authorization":f"Bearer {api}","Accept":"application/json"})
print("episodes status",st,"body",body[:400])
ep=json.loads(body)[0]["id"]
print("episode",ep)

# reset canary log
subprocess.run(["docker","compose","exec","-T","canary","sh","-c",": > /hits.log"])

st,play=http("GET",f"{BASE}/play/{ep}?api_token={audio}",timeout=120)
print("play status",st)
print("play body head:",play[:500])
hits=subprocess.run(["docker","compose","exec","-T","canary","sh","-c","cat /hits.log"],
                    capture_output=True,text=True).stdout.strip()
print("CANARY HITS:",repr(hits))
