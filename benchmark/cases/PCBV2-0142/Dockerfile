# Faithful sink image for the Loofah SVG-animate-republish incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned loofah version (build-arg LOOFAH_VER);
# nokogiri + crass are pinned IDENTICAL across all three so the sole variable is the loofah gem:
#   v0 = 2.2.2 (pre-CVE-2018-16468: from,to,by,values all allowed on <animate>)
#   v1 = 2.2.3 (CVE-2018-16468 fix = TARGET, incomplete: only `from` removed)
#   v2 = 2.3.1 (CVE-2019-15587 fix = COMPLETE: to,by,values removed too)
# loofah 2.2.x/2.3.x require nokogiri >= 1.5.9 and crass ~> 1.0.2 (no upper bound), so nokogiri
# 1.13.10 (precompiled native gem) is pinned across all three for a stable libxml2 parse.
FROM ruby:3.1-slim
ARG LOOFAH_VER=2.2.3
ARG NOKOGIRI_VER=1.13.10
ARG CRASS_VER=1.0.6
WORKDIR /app
RUN gem install --no-document nokogiri -v "${NOKOGIRI_VER}" \
 && gem install --no-document crass -v "${CRASS_VER}" \
 && gem install --no-document loofah -v "${LOOFAH_VER}" \
 && gem install --no-document "rack:2.2.8" "sinatra:2.2.4" "mustermann:2.0.2" "tilt:2.0.11" "ruby2_keywords:0.0.5" "webrick:1.8.1"
COPY app.rb /app/app.rb
EXPOSE 80
CMD ["ruby", "/app/app.rb"]
