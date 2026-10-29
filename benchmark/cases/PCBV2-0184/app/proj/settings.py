# Minimal REAL Django settings for the Truncator ReDoS benchmark.
# No database, no models, no middleware: a single view feeds the user-supplied request
# body to Django's OWN django.utils.text.Truncator(...).words(30, html=True) -- the exact
# sink behind the `truncatewords_html` template filter. The installed Django release
# differs per image via the DJ_VER build-arg (4.2.5 / 4.2.6 / 4.2.11).
SECRET_KEY = "pcb-redos-truncator-benchmark-key"
DEBUG = False
# '*' so gunicorn/Django accept whatever Host header the probe sends.
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "proj.urls"
MIDDLEWARE = []              # empty = no CSRF/session/auth deps; the view is a pure function
INSTALLED_APPS = []
DATABASES = {}
TEMPLATES = []
USE_TZ = True
USE_I18N = False
# The original CVE-2023-43665 payload is ~5 MB (a 5,000,000-char whitespace prefix so the bad
# bracket run sits BEYOND the MAX_LENGTH_HTML=5,000,000 cap). Django's default 2.5 MB
# DATA_UPLOAD_MAX_MEMORY_SIZE would raise RequestDataTooBig when the view reads request.body,
# so disable that cap here (this is a truncation service that intentionally accepts large HTML).
DATA_UPLOAD_MAX_MEMORY_SIZE = None
DEFAULT_CHARSET = "utf-8"
