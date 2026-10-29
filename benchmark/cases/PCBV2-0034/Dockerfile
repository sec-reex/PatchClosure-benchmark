# SUT is the published PyPI keras wheel (whole package), not a sliced snippet.
FROM python:3.11-slim

ARG KERAS_VERSION=3.13.2
RUN pip install --no-cache-dir "keras==${KERAS_VERSION}" "h5py" "numpy" "jax[cpu]"
ENV KERAS_BACKEND=jax

COPY server.py plant_flag.py /app/
WORKDIR /app
EXPOSE 3000
CMD ["python3", "/app/server.py"]
