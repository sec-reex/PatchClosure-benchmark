# Faithful sink image for the Sanitize foreign-content -> noscript incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned sanitize gem (build-arg SANITIZE_VER):
#   v0 = 5.2.0 (pre-CVE-2020-4054: math/svg foreign content NOT in :remove_contents -> leaks)
#   v1 = 5.2.1 (CVE-2020-4054 fix = TARGET, incomplete: added math/svg/plaintext/xmp to
#               :remove_contents so foreign-content leak is closed, but a custom allowlist that
#               permits `noscript` still keeps its contents -> noscript scripting-desync survives)
#   v2 = 6.0.1 (CVE-2023-23627 fix = COMPLETE: CleanElement now `node.unlink`s every <noscript>
#               regardless of the allowlist)
#
# Sanitize 5.2.x parses HTML5 via the `nokogumbo` gem (Nokogiri::HTML5 provided by nokogumbo);
# Sanitize 6.0.x requires nokogiri >= 1.12 (gumbo built in) and drops nokogumbo. That parser-backend
# change is inherent to the 5.x -> 6.x major bump and cannot be pinned identical; crass + the
# nokogiri libxml2/gumbo *scripting-disabled* parse rule (the root cause) are the constant. For
# v0/v1 the whole stack (nokogiri 1.13.10 + nokogumbo 2.0.5 + crass 1.0.6) is pinned IDENTICAL so
# the sole variable between the vulnerable and the incomplete-fix env is the sanitize gem itself.
ARG RUBY_TAG=2.7-slim
FROM ruby:${RUBY_TAG}
# PatchClosure: when the base is Debian bullseye (ruby:2.7-slim, v0/v1) it is EOL and its deb/security
# pool point-releases were purged from the mirrors (build-time apt 404 → build-essential silently
# failed to install → nokogumbo native-extension compile failed). Redirect to archive.debian.org.
# Guarded on bullseye so the bookworm-based v2 (ruby:3.1-slim) is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi
ARG SANITIZE_VER=5.2.1
ARG NOKOGIRI_VER=1.13.10
ARG CRASS_VER=1.0.6
ARG WITH_NOKOGUMBO=1
ARG NOKOGUMBO_VER=2.0.5
WORKDIR /app
RUN apt-get update -qq && apt-get install -y -qq build-essential >/dev/null 2>&1 || true
RUN gem install --no-document crass -v "${CRASS_VER}" \
 && gem install --no-document nokogiri -v "${NOKOGIRI_VER}" \
 && if [ "${WITH_NOKOGUMBO}" = "1" ]; then gem install --no-document nokogumbo -v "${NOKOGUMBO_VER}"; fi \
 && gem install --no-document sanitize -v "${SANITIZE_VER}" \
 && gem install --no-document "rack:2.2.8" "sinatra:2.2.4" "mustermann:2.0.2" "tilt:2.0.11" "ruby2_keywords:0.0.5" "webrick:1.8.1"
COPY app.rb /app/app.rb
EXPOSE 80
CMD ["ruby", "/app/app.rb"]
