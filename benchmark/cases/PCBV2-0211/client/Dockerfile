FROM python:3.11-slim
ARG U3_VERSION
WORKDIR /app
RUN pip install --no-cache-dir "urllib3==${U3_VERSION}" >/dev/null
# record the resolved version for provenance
RUN python -c "import urllib3; print('urllib3', urllib3.__version__)"
COPY probe.py /app/probe.py
COPY gateway.py /app/gateway.py
CMD ["python", "/app/gateway.py"]
