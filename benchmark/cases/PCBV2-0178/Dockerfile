# Real-library-wrap image for pydantic-ai-cve-2026-48782 (CVE-2026-46678 -> CVE-2026-48782).
#
# The SSRF guard is NOT lifted. Each version image `pip install`s the REAL published
# pydantic-ai distribution from PyPI (pydantic-ai-slim is pydantic-ai's core distribution and
# carries the identical real bytes of pydantic_ai/_ssrf.py, models/__init__.py and messages.py).
# app.py is a thin HTTP wrapper that calls the installed package's REAL download_item/safe_download.
# canary.py is a dual-stack metadata sidecar (needs only the stdlib, no pydantic-ai at runtime).
#
#   PYDANTIC_AI_VER=1.56.0   -> V0 (CVE-2026-25580 fix only; string-frozenset blocklist,
#                                   CVE-2026-46678 still open)
#   PYDANTIC_AI_VER=1.99.0   -> V1 (CVE-2026-46678 fix, _normalize_ip well-known-only)  <- target
#   PYDANTIC_AI_VER=1.102.0  -> V2 (CVE-2026-48782 fix, _embedded_ipv4s exhaustive)
FROM python:3.12-slim
ARG PYDANTIC_AI_VER=1.99.0
RUN pip install --no-cache-dir "pydantic-ai-slim==${PYDANTIC_AI_VER}"
WORKDIR /app
COPY app.py canary.py /app/
ENV PYTHONUNBUFFERED=1
