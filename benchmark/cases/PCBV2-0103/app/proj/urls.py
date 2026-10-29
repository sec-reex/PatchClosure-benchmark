# Real Django URLconf. /login is a genuine redirect view that gates the ?next=
# redirect target through Django's OWN is_safe_url() -- exactly what
# django.contrib.auth.views.login does internally -- and emits an
# HttpResponseRedirect. No Django source is copied; is_safe_url is imported from
# the installed django package (present under this name in 1.7.5/1.8.0/1.8.18).
from django.conf.urls import url
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.http import is_safe_url


def go(request):
    nxt = request.GET.get("next", "/")
    if is_safe_url(nxt, host=request.get_host()):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect("/")


def healthz(request):
    return HttpResponse("ok")


urlpatterns = [
    url(r"^login$", go),
    url(r"^healthz$", healthz),
    url(r"^$", healthz),
]
