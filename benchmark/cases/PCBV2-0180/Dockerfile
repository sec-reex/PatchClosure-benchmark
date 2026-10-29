# Faithful-core image for pyyaml-cve-2019-20477 (CVE-2017-18342 -> CVE-2019-20477).
# One Dockerfile; the PyYAML version is pinned per profile via the PYYAML_VERSION build arg
# (V0=3.13 pre-CVE-2017-18342, V1=5.1 the guard/target, V2=5.2 the CVE-2019-20477 fix) and the
# running loader role is chosen by HARNESS_VER. No app deps beyond the REAL PyYAML release: the
# guard under test IS PyYAML's own FullConstructor, exercised through the genuine yaml.load sink.
FROM python:3.11-slim
ARG PYYAML_VERSION
WORKDIR /app
RUN pip install --no-cache-dir "pyyaml==${PYYAML_VERSION}"
COPY harness.py /app/
ENV PYTHONUNBUFFERED=1
