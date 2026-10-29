# Faithful sink image for the rails-html-sanitizer select+style incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned rails-html-sanitizer version
# (build-arg RHS_VER); loofah + nokogiri are pinned IDENTICAL across all three so the sole
# variable is the sanitizer gem:
#   v0 = 1.4.2 (pre-CVE-2022-32209)
#   v1 = 1.4.3 (CVE-2022-32209 fix = TARGET, incomplete)
#   v2 = 1.4.4 (CVE-2022-23520 fix = COMPLETE)
# loofah 2.19.1 keeps the HTML4 (libxml2) parser (non-html5: Loofah has no html5_mode? here,
# so remove_safelist_tag_combinations' `!loofah_using_html5?` guard is TRUE), preserving the
# CDATA-under-<style> serialization that the mutation XSS depends on. nokogiri is pinned so
# the libxml2 recovery behavior is stable.
FROM ruby:3.1-slim
ARG RHS_VER=1.4.3
ARG LOOFAH_VER=2.19.1
ARG NOKOGIRI_VER=1.13.10
WORKDIR /app
RUN gem install --no-document nokogiri -v "${NOKOGIRI_VER}" \
 && gem install --no-document loofah -v "${LOOFAH_VER}" \
 && gem install --no-document crass -v 1.0.6 \
 && gem install --no-document rails-html-sanitizer -v "${RHS_VER}" \
 && gem install --no-document "rack:2.2.8" "sinatra:2.2.4" "mustermann:2.0.2" "tilt:2.0.11" "ruby2_keywords:0.0.5" "webrick:1.8.1"
COPY app.rb /app/app.rb
EXPOSE 80
CMD ["ruby", "/app/app.rb"]
