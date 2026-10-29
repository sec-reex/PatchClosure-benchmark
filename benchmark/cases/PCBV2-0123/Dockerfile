# Faithful-core: official python-slim + a pinned, UNMODIFIED gradio release.
# The version's own gradio.utils.is_in_or_equal() containment guard (the CVE sink)
# decides whether a /file= request escapes the allowed_paths directory.
FROM python:3.11-slim
ARG GRADIO_VER
# PINS: era-correct web-stack versions for this gradio release. gradio's own metadata
# leaves fastapi/pydantic/jinja2/uvicorn/huggingface_hub effectively unbounded, so a bare
# `pip install gradio==<old>` pulls 2025/2026 releases that break the old gradio at import
# (huggingface_hub>=1.0 dropped HfFolder) and at request time (jinja2/fastapi/starlette
# drift -> "unhashable type: dict" rendering the main template). Passed per-service.
ARG PINS=""
ENV GRADIO_ANALYTICS_ENABLED=False \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# Install the exact gradio release under test plus the era-pinned deps (gradio itself
# pins the matching gradio-client, so that resolves automatically).
RUN pip install --no-cache-dir "gradio==${GRADIO_VER}" ${PINS}
COPY app.py /app.py
ENV GRADIO_VER=${GRADIO_VER}
CMD ["python", "/app.py"]
