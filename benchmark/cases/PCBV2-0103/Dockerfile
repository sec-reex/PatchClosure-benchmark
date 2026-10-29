# REAL Django open-redirect benchmark image (CVE-2015-2317 -> CVE-2017-7233).
# Installs the REAL published Django release (per DJ_PIP build-arg) from PyPI on a
# Python-2.7 base (these are py2.7-era releases) and boots a REAL Django project via
# `manage.py runserver`. NO Django source is copied into the image -- is_safe_url is
# exercised straight out of the installed django package.
#   DJ_PIP=1.7.5  -> V0 (pre CVE-2015-2317: is_safe_url has NO leading-control-char check)
#   DJ_PIP=1.8.0  -> V1 (CVE-2015-2317 fix; TARGET; \@ basic-auth residual still open)
#   DJ_PIP=1.8.18 -> V2 (CVE-2017-7233 fix; validates raw AND backslash-normalised URL)
FROM python:2.7-slim
ARG DJ_PIP=1.8.0
ENV PYTHONUNBUFFERED=1 DJ_PIP=${DJ_PIP}
WORKDIR /app
# gunicorn 19.10.0 = last release supporting Python 2.7; a REAL production WSGI server that
# forwards the app's Location header verbatim (the dev `runserver`/wsgiref absolutizes it and
# would mask the scheme-relative open redirect).
RUN pip install --no-cache-dir "Django==${DJ_PIP}" "gunicorn==19.10.0"
COPY app/ /app/
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--access-logfile", "-", "proj.wsgi:application"]
