# Real HTTP sink image for codeinj_pyyaml_fullloader (CVE-2020-1747 -> CVE-2020-14343).
# Recipe only: the EXACT published PyYAML is pip-installed at a pinned version
# (build-arg PYYAML_VER) from PyPI -- NO vendored source, NO source-lift. A minimal
# real Flask service (app.py) parses attacker-supplied request bodies with the real,
# unmodified yaml.full_load. python:3.8-slim matches the 2020-era release line so the
# old sdists build cleanly.
FROM python:3.8-slim
ARG PYYAML_VER
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# PyYAML 5.4's sdist breaks under Cython 3.x (AttributeError: cython_sources), so pin
# Cython<3 + build without isolation. Harmless for 5.3/5.3.1 (they build the same way).
# This only affects how the EXACT published PyYAML is COMPILED, not its FullConstructor
# logic. Flask stack pinned to a Python-3.8-compatible line.
RUN pip install --no-cache-dir "cython<3.0" wheel setuptools && \
    pip install --no-cache-dir --no-build-isolation "PyYAML==${PYYAML_VER}" && \
    pip install --no-cache-dir "flask==1.1.4" "markupsafe==1.1.1" "itsdangerous==1.1.0" \
        "jinja2==2.11.3" "werkzeug==1.0.1" "click==7.1.2"
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 80
CMD ["python", "/app/app.py"]
