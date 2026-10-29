# PatchClosure-Bench ruby-rexml-cve-2014-8090 — REAL bundled REXML behind a REAL Ruby web app.
#
# Base = the OFFICIAL Ruby image at the exact patch version (build-arg RUBY_VER), so REXML is the
# REAL library bundled in that MRI release (V0=2.1.3, V1=2.1.4 CVE-2014-8080 fix = TARGET,
# V2=2.1.5 CVE-2014-8090 fix). The images ship a schema-v1 manifest that modern Docker refuses to
# pull directly, so they are loaded into the local daemon as `ruby:<ver>-official` via
# `skopeo copy docker://ruby:<ver> docker-daemon:ruby:<ver>-official` (see repro.log). WEBrick is
# in the 2.1.x stdlib, so no gems are installed — the web app is stdlib-only over the bundled REXML.
ARG RUBY_VER=2.1.4
FROM ruby:${RUBY_VER}-official
WORKDIR /app
COPY app/server.rb /app/server.rb
ENV PORT=3000
EXPOSE 3000
CMD ["ruby", "/app/server.rb"]
