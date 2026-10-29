# Faithful-core image for open-webui-cve-2026-54019 (CVE-2026-44560 -> CVE-2026-54019).
# One image; the running role (v0 / v1 / v2) is chosen by the PCB_VER env var.
FROM python:3.12-slim
RUN pip install --no-cache-dir "fastapi>=0.110,<0.116" "uvicorn>=0.27,<0.35"
WORKDIR /app/core
COPY core/ /app/core/
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app/core
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
