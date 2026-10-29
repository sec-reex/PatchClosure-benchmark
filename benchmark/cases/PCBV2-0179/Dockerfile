# Real pyLoad product image (PCBV2-0179).
# Installs the WHOLE upstream tree at the pinned commit from the GitHub
# archive tarball (same object fetch_source.sh downloads). Not raw file
# slices, not assemble.py, not a function harness.
# Long-running process: the real `pyload` web UI on :8000.
# Python 3.11: tarfile.extractall has no default 'data' filter, so the
# plugin-level UnTar check — not CPython — decides zip-slip.
FROM python:3.11-slim

ARG SHA
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV PYCURL_SSL_LIBRARY=openssl

RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full curl ca-certificates \
        build-essential pkg-config \
        libcurl4-openssl-dev libssl-dev libffi-dev \
        libjpeg-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Entire repo tarball (not individual source files).
RUN curl -fsSL "https://github.com/pyload/pyload/archive/${SHA}.tar.gz" -o /tmp/pyload.tar.gz \
    && mkdir -p /opt/pyload-src \
    && tar xzf /tmp/pyload.tar.gz -C /opt/pyload-src --strip-components=1 \
    && rm -f /tmp/pyload.tar.gz

WORKDIR /opt/pyload-src
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir ".[plugins]" \
    && python3 -c "import pyload, pyload.plugins.extractors.SevenZip, pyload.plugins.extractors.UnTar; print('site-packages', pyload.__file__)" \
    && rm -rf /opt/pyload-src

# Preseed userdir so runtime has no install wizard. Bind 0.0.0.0:8000.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /root/.pyload /downloads /data/dl \
    && (timeout 45 pyload --userdir /root/.pyload --storagedir /downloads --dry-run || true) \
    && if [ ! -f /root/.pyload/settings/pyload.cfg ]; then \
         timeout 45 pyload --userdir /root/.pyload --storagedir /downloads || true; \
       fi \
    && test -f /root/.pyload/settings/pyload.cfg \
    && sed -i -E 's/(ip host : "IP [Aa]ddress" = )localhost/\10.0.0.0/' /root/.pyload/settings/pyload.cfg \
    && grep -E 'ip host' /root/.pyload/settings/pyload.cfg

WORKDIR /root
EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
