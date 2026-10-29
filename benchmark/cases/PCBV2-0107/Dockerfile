# Faithful-core image for the Faraday build_exclusive_url host-scoping SSRF guard
# (CVE-2026-25765 -> CVE-2026-33637). One image per faraday version (ARG FARADAY_VERSION),
# three roles selected by ROLE:
#   ROLE=base      -> the trusted upstream the server is CONFIGURED to call (base-URL host).
#   ROLE=attacker  -> the INTERNAL-only service that serves ${PCB_FLAG} (must NOT be reachable
#                     via the fixed base URL; only via a host-override SSRF).
#   ROLE=server    -> a destination-pinned proxy that does
#                     Faraday.new(url:'http://trusted-base.pcb').get(<user target>)
#                     with the REAL per-version faraday gem chosen by FARADAY_VERSION.
# ruby:3.3-slim ships the net/http stack faraday's net_http adapter uses as the outbound sink.
# The REAL published gem bytes are installed via `gem install faraday -v <ver>` (pulls the
# faraday-net_http runtime dependency), so the server exercises the exact published bytes of
# faraday 2.14.0 (V0), 2.14.1 (V1, the CVE-2026-25765 fix / incomplete-fix TARGET) and
# 2.14.2 (V2, the CVE-2026-33637 fix; connection.rb byte-identical to 2.14.3).
FROM ruby:3.3-slim
ARG FARADAY_VERSION=2.14.1
RUN gem install faraday -v ${FARADAY_VERSION} --no-document
WORKDIR /app
COPY app.rb /app/
EXPOSE 8080
CMD ["ruby", "/app/app.rb"]
