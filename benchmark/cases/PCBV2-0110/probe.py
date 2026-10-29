#!/usr/bin/env python3
import http.client, json, socket, sys, time
HOST, PORT = "127.0.0.1", 34921
HTTP_TIMEOUT_S = 10.0
def probe(payload, label):
    data = payload.encode("utf-8")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(HOST, PORT, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=data,
                  headers={"Content-Type": "text/xml", "Content-Length": str(len(data))})
        r = c.getresponse()
        resp = r.read().decode("utf-8","replace")
        c.close()
        ms = (time.perf_counter()-t0)*1000.0
        print(f"{label}: in_len={len(payload)} -> {ms:.1f}ms timeout=False resp={resp[:160]!r}")
        return ms
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter()-t0)*1000.0
        print(f"{label}: in_len={len(payload)} -> {ms:.1f}ms timeout=True")
        return ms
    except OSError as e:
        print(f"{label}: OSError {e}")
        return -1
if __name__ == "__main__":
    kind = sys.argv[1] if len(sys.argv)>1 else "benign"
    if kind == "benign":
        p = '<?xml version="1.0"?>\n<note><to>hi</to><body>hello &amp; world &lt;ok&gt; &quot;q&quot;</body></note>'
    elif kind == "residual_lt":
        p = "<r>%s</r>" % ("&lt;" * 120000)
    elif kind == "residual_amp":
        p = "<r>%s</r>" % ("&amp;" * 120000)
    elif kind == "residual_quote":
        p = "<r>%s</r>" % ("&quot;" * 120000)
    elif kind == "residual_apos":
        p = "<r>%s</r>" % ("&apos;" * 120000)
    elif kind == "residual_numdec":
        p = "<r>%s</r>" % ("&#60;" * 120000)
    elif kind == "residual_numhex":
        p = "<r>%s</r>" % ("&#x3c;" * 120000)
    elif kind == "residual_attr":
        p = '<r a="%s">x</r>' % ("&lt;" * 120000)
    else:
        p = sys.argv[2] if len(sys.argv)>2 else "<r/>"
    probe(p, kind)
