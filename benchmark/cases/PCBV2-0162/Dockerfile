# Whole OpenStack Nova at a pinned commit (library CVE).
# Installs the FULL git tree (GitHub archive of openstack/nova), then
# `pip install --no-deps .` so `import nova; import nova.virt.images` loads
# from site-packages — not two raw.githubusercontent.com files + stubs.
# Thin HTTP consumer (server.py) calls nova.virt.images.fetch_to_raw.
# Convert/info sink is the real qemu-img from qemu-utils.
FROM python:3.11-slim-bookworm

ENV PCB_VERSION=unset
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PBR_VERSION=29.0.0+pcb

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      qemu-utils curl ca-certificates git \
      gcc libc6-dev libffi-dev libssl-dev \
      libxml2-dev libxslt1-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN pip install --no-cache-dir -r /tmp/requirements-runtime.txt \
 && rm -f /tmp/requirements-runtime.txt

# COMMIT after the shared pip layer so v0/v1/v2 reuse the dep image.
ARG COMMIT
# Full nova tree at COMMIT (entire archive, not individual source files).
RUN test -n "${COMMIT}" \
 && curl -fsSL "https://github.com/openstack/nova/archive/${COMMIT}.tar.gz" -o /tmp/nova.tar.gz \
 && mkdir -p /opt/nova-src \
 && tar xzf /tmp/nova.tar.gz -C /opt/nova-src --strip-components=1 \
 && rm -f /tmp/nova.tar.gz \
 && test -f /opt/nova-src/nova/virt/images.py \
 && test -f /opt/nova-src/setup.cfg \
 && test -d /opt/nova-src/nova/compute \
 && test -d /opt/nova-src/nova/image \
 && test -d /opt/nova-src/nova/privsep

WORKDIR /opt/nova-src
# Install the whole tree, then prove import from site-packages (not cwd /opt/nova-src).
RUN pip install --no-cache-dir --no-deps . \
 && cd /tmp \
 && python -c "\
import nova, nova.virt.images, sys; \
print('nova', nova.__file__); \
print('images', nova.virt.images.__file__); \
assert 'site-packages' in (nova.__file__ or ''), nova.__file__; \
assert nova.virt.images.__file__.endswith('virt/images.py'), nova.virt.images.__file__; \
assert '/app/' not in (nova.virt.images.__file__ or ''); \
print('import-ok', sys.version.split()[0])" \
 && rm -rf /opt/nova-src

WORKDIR /app
COPY server.py /app/server.py

ENV CANARY_PATH=/canary/secret.txt \
    PORT=8080

# Plant per-run canary OUTSIDE any image store, then the thin HTTP front-end.
ENTRYPOINT ["/bin/sh","-c","\
  mkdir -p /canary && \
  printf '%s' \"${PCB_FLAG:?set PCB_FLAG to the per-run canary token}\" > /canary/secret.txt && \
  chmod 644 /canary/secret.txt && \
  exec python /app/server.py"]
