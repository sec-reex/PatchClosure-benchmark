# Standard Django WSGI entrypoint, served by gunicorn (a real production WSGI server).
# A gunicorn sync worker runs one request at a time to completion, so a catastrophic
# Truncator input holds the worker (and the HTTP response) for the full regex compute
# time -- the ReDoS is observable as external request latency.
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proj.settings")
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
