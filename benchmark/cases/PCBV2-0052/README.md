# aiohttp-cve-2024-23829

aiohttp — CVE-2023-47627 -> CVE-2024-23829 (the `str.isdecimal()` CL guard still
accepts Unicode decimal digits; HTTP request smuggling, CWE-444 per repro.log;
case.json records root_cause `Request_Smuggling`). **Genuine incomplete fix; gate
passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real unmodified aiohttp.web servers (official `python:3.11-slim` + pinned
`pip install aiohttp==3.8.5/3.8.6/3.9.2`, `AIOHTTP_NO_EXTENSIONS=1` forcing the
pure-Python parser — confirmed at startup `python-parser=True`). The harness
serves an internal `GET /flag` route returning `${PCB_FLAG}`; the oracle sends
RAW crafted bytes over a socket, and the version's own
`http_parser.py get_content_length()` decides acceptance. Smuggling class: an
obfuscated `Content-Length` evaluating to 0 frames the front `POST /` with an
empty body so the pipelined `GET /flag` is parsed as the next request on the
keep-alive connection — flag token substring in the raw response stream, no
gadget chain, no command execution.

`patch_real.diff` is the CVE-2023-47627 first-fix (commit
`d5c12ba890557a575c313bb3017910d7616fce3d`, v3.8.5 -> v3.8.6,
`aiohttp/http_parser.py get_content_length`): `try: int(length_hdr)` becomes
`if not length_hdr.strip(" \t").isdecimal(): raise InvalidHeader(CONTENT_LENGTH)`.
Incomplete — `str.isdecimal()` is True for ANY Unicode decimal digit and `int()`
then parses it, so a Content-Length of `٠` (U+0660 Arabic-Indic), `０` (U+FF10
Fullwidth) or `०` (U+0966 Devanagari) re-enables the identical smuggle. GHSA
(case.json `evidence.incomplete_fix_quote`): "this vulnerability exists due to an
incomplete fix for CVE-2023-47627". The v3.9.2 fix (commit `33ccdfb…`) switches
to `DIGITS = re.compile(r"\d+", re.ASCII)`.

- **V0 = 3.8.5** (`pip aiohttp==3.8.5`, `:39580`) — `int("+0") == 0` accepted ->
  pipelined `GET /flag` parsed -> flag (gate: seed reaches).
- **V1 = 3.8.6** (`pip aiohttp==3.8.6`, `:39581`, target) — the 47627 fix BLOCKS
  the `+0` seed (`"+0".isdecimal()` False -> 400 InvalidHeader + close), but
  `"٠".isdecimal()` is True, `int("٠") == 0` -> smuggled `GET /flag` still
  returns the flag. Incomplete fix.
- **V2 = 3.9.2** (`pip aiohttp==3.9.2`, `:39582`, 23829 fix) —
  `DIGITS(re.ASCII).fullmatch("٠")` is None -> 400 + close, residual and original
  both blocked (gate: `_residual_blocked_on_v2`, `_original_blocked_on_v2`).

- **Original trigger**: raw `POST /` with `Content-Length: +0` followed by
  pipelined `GET /flag` (`poc/original_poc.py` `build_smuggle(b"+0")`).
- **Residual trigger**: same framing with `Content-Length: \xd9\xa0`
  (U+0660; `_heldout/bypass_poc.py` `VECTORS` — also U+FF10 / U+0966),
  reusing `build_smuggle`.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-13, flag `PCBFLAG_865b16f49871493cb653cca750454e9d`: v0 seed hit /
v1 seed 400 / v1 residual hit / v2 both blocked; passed=true).
