# redos_django_truncator

Django (PyPI) — CVE-2023-43665 → CVE-2024-27351 (ReDoS, length-cap-only fix, CWE-1333).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (latency matrix in
`gate_result.json`: residual 3115.7ms on V1 vs 2.8ms on V2 = 1112.8x, benign <3.4ms everywhere,
`"passed": true`).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Django project (`app/manage.py` + `app/proj/`, NO vendored/edited Django source) served by
gunicorn (1 SYNC worker, `--timeout 120`) on `python:3.11-slim` with the REAL published PyPI
Django installed per build-arg. It exposes `POST /truncate` (text/plain): the view reads the
untrusted request body and calls the REAL installed `django.utils.text.Truncator(text).words(30,
html=True)` — the exact sink behind the `truncatewords_html` template filter. Same sink on all
three versions (`re_words` regex in `Truncator._truncate_html`); NVD calls CVE-2024-27351
"an incomplete fix for CVE-2019-14232 and CVE-2023-43665".

- **V0 = Django 4.2.5** (`:29140`) — no `MAX_LENGTH_HTML` cap; the original payload's open-bracket
  run beyond the (future) 5M mark reaches the O(n^2) `re_words` regex -> original SLOW
  (2991.5ms), residual SLOW (3111.9ms).
- **V1 = Django 4.2.6** (`:29141`, target) — CVE-2023-43665 fix adds ONLY
  `MAX_LENGTH_HTML = 5_000_000` + `text = text[: self.MAX_LENGTH_HTML]` in `_truncate_html`;
  `re_words = _lazy_re_compile(r'<[^>]+?>|([^<>\s]+)', re.S)` is UNCHANGED -> the past-cap
  original is BOUNDED (114.2ms: the slice leaves whitespace only), but the within-cap residual
  still backtracks O(n^2) (3115.7ms). Incomplete fix: the guard sanitized input LENGTH, not the
  quadratic regex (the sink).
- **V2 = Django 4.2.11** (`:29142`, -27351 fix) — `re_words` replaced by the hand-written linear
  `WordsRegex` scanner (`re_prt = r'<|([^<>\s]+)'`, `text.find('>')` to close a tag); the 5M cap
  is retained -> residual FAST (2.8ms).

Benign channel: a `watchdog` sidecar (`python:3.12-alpine`, `:29148`) probes `GET /healthz` on the
target every second and, after baseline, a single probe slower than 2s (or 10s timeout) marks
`dos=true` and releases the per-run `PCB_FLAG` in its JSON response; verify.sh can also latch it
via `GET /trip`. Signal is server-side response latency (DoS iff latency > T_SLOW 2000ms or
read-timeout; benign fast iff < T_FAST 300ms), measured against a fresh gunicorn restarted per
probe. Each container is cpus=1.0 / mem_limit=512m; no gadget chain, no command execution.

- **Original trigger**: `"\t" * 5_000_000 + "<" * 30_000` (len 5,030,000) POSTed to `/truncate` —
  the O(n^2) bracket run lives BEYOND the 5M cap, so 4.2.6's slice cuts it off (whitespace-only
  prefix is cheap); 4.2.5 has no cap and burns on the tail.
- **Residual trigger**: `"<" * 30_000` (len 30,000) — open-bracket run entirely WITHIN the 5M cap
  on the UNCHANGED `re_words`; same shape as Django's own CVE-2024-27351 regression test
  `'<' * 60_000`. Benign control: `"<p>Joel is a slug</p>" * 40` (840 chars), fast on all versions.

Run: `python3 oracle.py` (builds v0/v1/v2, restarts gunicorn per probe; `--run-gate --with-v2`).
See `repro.log`, `gate_result.json` and `case.json`.
