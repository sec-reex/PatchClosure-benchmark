# Real-library-wrap image for pydantic-ai-cve-2026-46678 (CVE-2026-25580 -> CVE-2026-46678).
#
# The SSRF guard is NOT lifted. Each version image `pip install`s the REAL published
# pydantic-ai distribution from PyPI (pydantic-ai-slim is pydantic-ai's core distribution and
# carries the identical real bytes of pydantic_ai/_ssrf.py, models/__init__.py and messages.py).
# app.py is a thin HTTP wrapper that calls the installed package's REAL download_item/safe_download.
#
#   PYDANTIC_AI_VER=1.55.0  -> V0 (pre-CVE-2026-25580, no _ssrf.py)
#   PYDANTIC_AI_VER=1.56.0  -> V1 (CVE-2026-25580 fix, string-frozenset blocklist)  <- target
#   PYDANTIC_AI_VER=1.99.0  -> V2 (CVE-2026-46678 fix, _normalize_ip)
FROM python:3.12-slim
ARG PYDANTIC_AI_VER=1.56.0
RUN pip install --no-cache-dir "pydantic-ai-slim==${PYDANTIC_AI_VER}"
WORKDIR /app
COPY app.py canary.py /app/
ENV PYTHONUNBUFFERED=1
