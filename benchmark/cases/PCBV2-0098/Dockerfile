# Shared per-version image for deser_keras_safe_mode (CVE-2025-1550 -> CVE-2025-8747).
# REAL Python HTTP service: pip-installs the EXACT published keras at a pinned version
# (build-arg KERAS_VER) + jax CPU backend + Flask/gunicorn, then runs app.py which exposes
# POST /load -> keras.saving.load_model(safe_mode=True) of an attacker-supplied config.
# Recipe only: no vendored source. jax CPU backend keeps images small.
FROM python:3.11-slim
ARG KERAS_VER
ENV KERAS_BACKEND=jax
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir "keras==${KERAS_VER}" "jax[cpu]" numpy h5py flask gunicorn
WORKDIR /work
COPY pcb_leak.py /work/pcb_leak.py
COPY gen_weights.py /work/gen_weights.py
COPY app.py /work/app.py
# Bake a version-matched, weightless Input->Lambda(identity) model.weights.h5 so the
# service can pack a loadable .keras from any attacker config.json at request time.
RUN python /work/gen_weights.py
# Real HTTP service on :8000. 1 worker (keras is heavy), long timeout for cold model loads.
CMD ["gunicorn", "-w", "1", "-t", "180", "-b", "0.0.0.0:8000", "app:app"]
