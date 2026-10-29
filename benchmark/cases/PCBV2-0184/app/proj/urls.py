# Real Django URLconf. POST /truncate is a genuine HTML-truncation endpoint: it feeds the
# untrusted request body to Django's OWN django.utils.text.Truncator(...).words(30, html=True)
# -- exactly what the `truncatewords_html` template filter calls internally to safely shorten
# user/CMS HTML. No Django source is copied; Truncator is imported from the installed package
# (4.2.5 / 4.2.6 / 4.2.11 per image). The regex runs SYNCHRONOUSLY inside the gunicorn sync
# worker, so a catastrophic-backtracking input HANGS the HTTP response = server-side ReDoS.
import time

import django
from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.utils.text import Truncator


def truncate(request):
    # The untrusted HTML arrives as the raw request body (text/plain) so the ~5 MB original
    # payload isn't blown up by form url-encoding. This mirrors a real app truncating user HTML.
    text = request.body.decode("utf-8", "replace")
    t0 = time.perf_counter()
    result = Truncator(text).words(30, html=True)      # <-- real Django ReDoS sink
    server_ms = (time.perf_counter() - t0) * 1000.0
    return JsonResponse({
        "server_ms": round(server_ms, 3),
        "input_len": len(text),
        "truncated_len": len(result),
        "django_version": django.get_version(),
    })


def healthz(request):
    return HttpResponse("ok " + django.get_version())


urlpatterns = [
    path("truncate", truncate),
    path("healthz", healthz),
    path("", healthz),
]
