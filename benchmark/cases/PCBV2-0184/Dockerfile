# REAL Django Truncator ReDoS benchmark image (CVE-2023-43665 -> CVE-2024-27351).
# Installs the REAL published Django release (per DJ_VER build-arg) from PyPI on python:3.11-slim
# and boots a REAL Django project (proj/ + manage.py) under gunicorn. NO Django source is copied
# into the image -- django.utils.text.Truncator is exercised straight out of the installed package.
#   DJ_VER=4.2.5  -> V0 (pre CVE-2023-43665: re_words regex, NO input cap)
#   DJ_VER=4.2.6  -> V1 (CVE-2023-43665 fix; TARGET; adds MAX_LENGTH_HTML=5M cap, regex UNCHANGED)
#   DJ_VER=4.2.11 -> V2 (CVE-2024-27351 fix; replaces re_words with the linear WordsRegex scanner)
FROM python:3.11-slim
ARG DJ_VER
ENV PYTHONUNBUFFERED=1 DJ_VER=${DJ_VER}
WORKDIR /app
RUN pip install --no-cache-dir "Django==${DJ_VER}" "gunicorn==21.2.0" && \
    python -c "import django; print('django', django.get_version())"
COPY app/ /app/
EXPOSE 8000
# Single SYNCHRONOUS worker so a catastrophic Truncator input holds the response (measurable ReDoS
# latency). --timeout 120 keeps the worker alive well past the oracle's 10s measurement window so
# the ReDoS latency is measured, not masked by a worker-kill.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--timeout", "120", "--access-logfile", "-", "proj.wsgi:application"]
