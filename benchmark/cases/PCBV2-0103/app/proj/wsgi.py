# Standard Django WSGI entrypoint, served by gunicorn (a real production WSGI server).
# gunicorn passes the app's Location header through verbatim -- unlike Django's dev
# `runserver` (wsgiref), which absolutizes relative Location headers and would mask the
# scheme-relative open redirect. This mirrors how CVE-2015-2317 manifests in production.
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proj.settings")
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
