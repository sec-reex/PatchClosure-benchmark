# Faithful-core: official python-slim + a pinned aiohttp release, pure-Python parser.
FROM python:3.11-slim
ARG AIOHTTP_VER
ENV AIOHTTP_NO_EXTENSIONS=1
# Install the exact aiohttp release under test. AIOHTTP_NO_EXTENSIONS at runtime forces
# the pure-Python parser regardless of whether the wheel shipped the C extension.
RUN pip install --no-cache-dir "aiohttp==${AIOHTTP_VER}"
COPY harness.py /harness.py
ENV AIOHTTP_VER=${AIOHTTP_VER}
CMD ["python", "/harness.py"]
