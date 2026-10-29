# DBI PCB case: CVE-2026-10879 -> CVE-2026-14739 (preparse heap overflow)
# Installs the REAL DBI CPAN distribution at a pinned version and runs the
# REAL preparse() XS path with N '?' placeholders.
#   DBI_VERSION=1.647 -> V0 (newSV(strlen*3): overflow from ~1.1K placeholders)
#   DBI_VERSION=1.648 -> V1 (CVE-2026-10879 fix: strlen*6+16; overflow from ~11.1K) <- target
#   DBI_VERSION=1.650 -> V2 (CVE-2026-14739 fix: strlen*7+16 + 99999 hard limit)
FROM perl:5.40-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sL https://cpanmin.us | perl - -q --notest App::cpanminus \
    && rm -rf /root/.cpanm

ARG DBI_VERSION=1.648
RUN cpanm -q --notest DBI@${DBI_VERSION} \
    && rm -rf /root/.cpanm

RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY probe.pl /app/probe.pl
COPY gateway.py /app/gateway.py
CMD ["python3", "/app/gateway.py"]
