# Real-library-wrap: pip-installed REAL WebOb bytes on Python 3.11.
# WEBOB_VERSION selects the profile (1.8.7 / 1.8.8 / 1.8.10).
# python:3.11 is REQUIRED: the CVE-2026-44889 residual depends on the
# Python 3.10+ urlsplit() behavior that strips ASCII tab/CR/LF.
FROM python:3.11.13-slim-bookworm

ARG WEBOB_VERSION=1.8.8
RUN pip install --no-cache-dir --retries 5 --timeout 60 "WebOb==${WEBOB_VERSION}"

# Fail the build loudly if the exact requested version is not what got installed.
RUN test "$(python -c 'import importlib.metadata as m;print(m.version("webob"))')" = "${WEBOB_VERSION}" \
    && echo "verified webob==${WEBOB_VERSION}"

WORKDIR /app
COPY wsgi_app.py /app/wsgi_app.py

EXPOSE 8000
CMD ["python", "/app/wsgi_app.py"]
