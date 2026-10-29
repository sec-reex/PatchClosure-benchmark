# cpython-urllib-crlf-header-injection-cve-2019-18348

CPython stdlib (urllib.request / http.client) — CVE-2019-9947 -> CVE-2019-18348 (CRLF/obs-fold HTTP
header injection, CWE-93 / CWE-113). **Genuine incomplete fix; gate passed on real Docker; trigger is
a real CLI invocation (`docker compose exec python /client.py <url>`, run_mode `real-cli-nonhttp`),
not an inbound HTTP request.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real UNMODIFIED official `python:3.7.x-slim-stretch` images drive `urllib.request.urlopen(attacker_url)`.
The canary is an ssrf-sidecar: an internal-only raw-socket HTTP server (`sidecar.py`, fixed at
`10.89.0.2:80` on compose net `pcbnet`, no host port) that reads literal request bytes, unfolds
obs-fold continuations, and returns `${PCB_FLAG}` iff the outgoing request carries the smuggled
`X-PCB-Auth: PCB-AUTH-7f3a` header a legitimate urllib client never sends (docker-compose.yml:32-44).
Same sink across the chain: http.client's `_contains_disallowed_url_pchar_re`
(`re.compile('[\x00-\x20\x7f]')`) control-char check.

`patch_real.diff` is the upstream CVE-2019-9740/9947 fix (commit `7e200e0763f5b71c199aaf98bd5588f291585619`,
bpo-30458): `_contains_disallowed_url_pchar_re` + an InvalidURL raise in `HTTPConnection.putrequest` —
scanning the URL **path** only; the netloc-derived `self.host` that later becomes the auto `Host:`
header was never scanned, and `putheader`'s `_is_illegal_header_value` deliberately ALLOWS obs-fold
(`\r\n` + space/tab). Debian stretch (glibc 2.24, pre-CVE-2016-10739) is required and faithful: the
advisory states the host variant "can be exploited only when glibc flaw CVE-2016-10739 is not fixed"
(case.json `environment_note`).

- **V0 = python 3.7.2** (`python:3.7.2-slim-stretch`) — no `_validate_path`: path-CRLF accepted,
  `X-PCB-Auth` reaches the sidecar -> seed hits the flag.
- **V1 = python 3.7.4** (`python:3.7.4-slim-stretch`, target) — `_validate_path` rejects control chars
  in the path (InvalidURL, seed BLOCKED), but the HOST component is unchecked -> host-CRLF/obs-fold
  still smuggles `X-PCB-Auth` -> the CVE-2019-18348 residual hits the flag. Incomplete fix.
- **V2 = python 3.7.8** (`python:3.7.8-slim-stretch`, 18348 fix) — adds `_validate_host` in
  `HTTPConnection.__init__` -> residual raises InvalidURL, BLOCKED. (The sidecar itself runs 3.7.8 in
  all profiles; clients just `sleep infinity` — the oracle drives each attack via `docker compose exec`.)

- **Original trigger**: URL with CRLF in the PATH/request-line —
  `http://10.89.0.2:80/x HTTP/1.1\r\nX-PCB-Auth: PCB-AUTH-7f3a\r\nZ:` (poc/original_poc.py
  `build_url()`; the trailing `Z:` dummy header absorbs the `' HTTP/1.1'` http.client appends).
- **Residual trigger**: URL with CRLF/obs-fold in the HOST component —
  `http://10.89.0.2\r\n\tX-PCB-Auth: PCB-AUTH-7f3a\r\n\t:80/` (`_heldout/bypass_poc.py` `build_url()`,
  tab continuation; a space-continuation variant is also provided — both pass `_is_illegal_header_value`
  while `_get_hostport` keeps `:80` and pre-10739 glibc resolves the control-char host to 10.89.0.2).

> NOTE: `patch_real.diff`'s header labels the fix commit "CVE-2019-9740" while case.json names the
> original CVE of this chain as CVE-2019-9947. Not a version mismatch: the same bpo-30458 commit and
> its `_contains_disallowed_url_pchar_re` guard cover both the query (9740) and path (9947) variants —
> INCOMPLETE_FIX_ANALYSIS.md says so explicitly ("注释写的是 CVE-2019-9740，同一正则也盖住 9947").

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`
(gate 2026-07-13: original PATH-CRLF flag@v0 / blocked@v1; residual HOST-CRLF obs-fold flag@v1 /
blocked@v2 `_validate_host`; original also blocked@v2).
