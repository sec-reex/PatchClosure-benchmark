# Whole OpenStack Glance at a pinned commit (library/app CVE).
# GitHub archive of the FULL openstack/glance tree, then
# `pip install --no-deps .` so `from glance.common import store_utils`
# loads from site-packages — not a raw store_utils.py + stubs.
# Thin HTTP consumer (server.py) calls validate_external_location
# then reads via the real glance_store filesystem backend.
#
#   v0 = 81b3c04e  (pre-CVE-2014-9493: no scheme guard)
#   v1 = 4afdb017  (file:// blocked; filesystem:// residual = CVE-2015-1195)
#   v2 = a2d986b9  (filesystem:// also blocked)
FROM python:2.7

ENV PCB_VERSION=unset
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PBR_VERSION=2015.1+pcb

COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN pip install --no-cache-dir -r /tmp/requirements-runtime.txt \
 && rm -f /tmp/requirements-runtime.txt
COPY extra-runtime.txt /tmp/extra-runtime.txt
RUN pip install --no-cache-dir -r /tmp/extra-runtime.txt \
 && rm -f /tmp/extra-runtime.txt
# After pip layers so Oslo-alias tweaks do not bust the wheel cache.
COPY sitecustomize.py /usr/local/lib/python2.7/site-packages/sitecustomize.py

ARG COMMIT
RUN test -n "${COMMIT}" \
 && python -c "import ssl,urllib2; \
ctx=ssl._create_unverified_context(); \
u='https://github.com/openstack/glance/archive/%s.tar.gz' % '${COMMIT}'; \
open('/tmp/glance.tar.gz','wb').write(urllib2.urlopen(u,context=ctx).read())" \
 && mkdir -p /opt/glance-src \
 && tar xzf /tmp/glance.tar.gz -C /opt/glance-src --strip-components=1 \
 && rm -f /tmp/glance.tar.gz \
 && test -f /opt/glance-src/glance/common/store_utils.py \
 && test -f /opt/glance-src/setup.cfg \
 && test -d /opt/glance-src/glance/api \
 && test -d /opt/glance-src/glance/db \
 && test -d /opt/glance-src/glance/cmd

WORKDIR /opt/glance-src
# Install the whole tree, then prove import from site-packages (not cwd).
RUN pip install --no-cache-dir --no-deps . \
 && cd /tmp \
 && python -c "\
import sitecustomize; \
from glance.common import store_utils; \
import glance, sys; \
print('glance', glance.__file__); \
print('store_utils', store_utils.__file__); \
assert 'site-packages' in (store_utils.__file__ or ''), store_utils.__file__; \
assert store_utils.__file__.endswith('common/store_utils.py') or store_utils.__file__.endswith('common/store_utils.pyc'); \
print('import-ok', sys.version.split()[0])" \
 && rm -rf /opt/glance-src

WORKDIR /app
COPY server.py /app/server.py

ENV CANARY_PATH=/canary/secret.txt \
    GLANCE_DATADIR=/var/lib/glance/images \
    PORT=8080

ENTRYPOINT ["/bin/sh","-c","\
  mkdir -p /canary /var/lib/glance/images && \
  printf '%s' \"${PCB_FLAG:?set PCB_FLAG to the per-run canary token}\" > /canary/secret.txt && \
  chmod 644 /canary/secret.txt && \
  exec python /app/server.py"]
