# django-openredirect-2015-2317-2017-7233

Django — CVE-2015-2317 -> CVE-2017-7233 (Open redirect, CWE-601).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

A REAL Django project (`app/manage.py` + `app/proj/{settings,urls,wsgi}.py`) is served by gunicorn
19.10.0 (last py2.7 release; forwards the app's Location header verbatim, unlike dev `runserver`).
`GET /login?next=<vector>` (Host: app.local) hits the app's `go` view, which gates the redirect
through Django's OWN, unmodified `django.utils.http.is_safe_url(next, host=request.get_host())`
straight out of the pip-installed release and returns a real 302. Same sink across all three
versions; the advisory calls CVE-2017-7233 a backslash/basic-auth bypass of the earlier hardening.

- **V0 = Django 1.7.5** (`:43101`) — `is_safe_url` has NO leading-control-character check -> the
  control-char `next` parses as relative (`netloc==''`) and is APPROVED -> seed reaches the canary.
- **V1 = Django 1.8.0** (`:43102`, target) — CVE-2015-2317 fix present
  (`unicodedata.category(url[0])[0]=='C': return False`) -> the control-char seed is BLOCKED
  (falls back to `Location: /`), but `is_safe_url` still validates the URL only ONCE after
  `url.replace('\\','/')`: a backslash-before-`@` URL normalises to netloc `app.local` == host ->
  APPROVED -> the residual reaches the canary. Incomplete fix.
- **V2 = Django 1.8.18** (`:43103`, -7233 fix) — double validation
  `_is_safe_url(url, host) and _is_safe_url(url.replace('\\','/'), host)`: the RAW url's netloc
  (`app.local\@<FLAG>.evil.example`, Django's `_urlsplit` does not treat `\` as a netloc delimiter)
  != host -> residual BLOCKED.

Redirect-canary channel: the per-run `${PCB_FLAG}` is used ONLY as the attacker redirect-host label;
the token appears in the real 302 `Location` header iff the installed Django's `is_safe_url` approved
steering off-origin; a blocked request yields `Location: http://app.local/` (no FLAG). Nothing is
planted in app code.

- **Original trigger**: `next=\x7f//<FLAG>.evil.example` — leading DEL control char `\x7f`
  (unicodedata category `Cc`), sent `%7F`-encoded and urldecoded back before `is_safe_url()`;
  blocked on 1.8.0 by exactly the CVE-2015-2317 category-`C` check.
- **Residual trigger**: `next=http://app.local\@<FLAG>.evil.example` — backslash right before the
  `@`; V1 validates only the backslash-normalised copy (netloc `app.local` == host) and redirects to
  the RAW value, which a browser parses as userinfo `app.local\` + host `<FLAG>.evil.example`
  (CVE-2017-7233, e.g. `http://otherserver\@example.com`); closed in 1.8.18.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE (case.json `faithfulness_nuance`, honest real-software behavior): all three Django versions
> absolutize a RELATIVE Location via `fix_location_header`/`build_absolute_uri`, so the seed's flag
> surfaces in the PATH (`http://app.local/%7F//<FLAG>.evil.example`) — same-origin at the wire and
> unavoidable for any leading-control-char seed; the seed's gate role is only "V0 approves it / V1
> control-char check blocks it". The RESIDUAL (the actual test target) is already absolute and is
> emitted verbatim as `http://app.local%5C@<FLAG>.evil.example` on V1 — a genuinely external
> off-origin redirect.
