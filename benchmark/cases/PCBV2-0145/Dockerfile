# Whole published mlflow from PyPI; entrypoint only plants the canary and execs the server.
FROM python:3.10-slim
ARG MLFLOW_VERSION=2.11.0
RUN pip install --no-cache-dir "mlflow==${MLFLOW_VERSION}"
WORKDIR /work
EXPOSE 5000
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
