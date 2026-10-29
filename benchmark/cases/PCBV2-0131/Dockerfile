# Faithful-core image for jinja2-cve-2019-10906 (CVE-2016-10745 -> CVE-2019-10906).
# One Dockerfile; the Jinja2 version is pinned per profile via the JINJA_VERSION build
# arg (V0=2.7.3 pre-CVE-2016-10745, V1=2.8.1 the str.format fix / TARGET, V2=2.10.1 the
# CVE-2019-10906 str.format_map fix) and the running role is chosen by HARNESS_VER. No app
# deps beyond the REAL Jinja2 release: the guard under test IS Jinja2's own
# SandboxedEnvironment, exercised through the genuine env.from_string(...).render() sink.
# python:3.7-slim is compatible with the whole 2.7-2.10 range; MarkupSafe pinned to 1.1.1.
FROM python:3.7-slim
ARG JINJA_VERSION
WORKDIR /app
RUN pip install --no-cache-dir "jinja2==${JINJA_VERSION}" "markupsafe==1.1.1"
COPY harness.py render_once.py /app/
ENV PYTHONUNBUFFERED=1
