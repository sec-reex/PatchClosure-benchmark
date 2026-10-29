# Minimal REAL Django settings for the is_safe_url open-redirect benchmark.
# No database, no template engine, no middleware needed: the single view calls
# Django's OWN django.utils.http.is_safe_url on the ?next= parameter and returns
# an HttpResponseRedirect. Works identically on Django 1.7.5 / 1.8.0 / 1.8.18
# (the installed release differs per image via the DJ_PIP build-arg).
SECRET_KEY = "pcb-open-redirect-benchmark-key"
DEBUG = False
# '*' so runserver accepts whatever Host header the probe sends (the oracle sends
# Host: app.local, so request.get_host() -> 'app.local', the app's own "safe" host).
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "proj.urls"
MIDDLEWARE_CLASSES = ()          # Django 1.7/1.8 name; empty = no auth/session deps
MIDDLEWARE = ()                  # Django 1.10+ name (harmless on 1.7/1.8)
INSTALLED_APPS = ()
DATABASES = {}
USE_TZ = True
