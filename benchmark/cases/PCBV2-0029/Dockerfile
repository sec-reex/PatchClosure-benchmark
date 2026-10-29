# Faithful-core WEBrick env for PatchClosure-Bench webrick-crlf-2017-17742-2019-16254.
# The incomplete-fix boundary lives in Ruby MRI's BUNDLED webrick (the standalone
# webrick gem tags jump straight from no-check (1.4.2) to the complete /[\r\n]/ check
# (1.4.4), skipping the /\r\n/-only state), so each version = a matching ruby:2.5.x image:
#   V0 = ruby:2.5.0-slim  webrick 1.4.2, NO check_header          (pre CVE-2017-17742)
#   V1 = ruby:2.5.1-slim  check_header  =~ /\r\n/  (CRLF pair only) (CVE-2017-17742 = TARGET)
#   V2 = ruby:2.5.8-slim  check_header  /[\r\n]/   (any CR or LF)   (CVE-2019-16254 complete)
# webrick ships in the ruby 2.5 stdlib -> no gem install needed.
ARG RUBY_TAG
FROM ruby:${RUBY_TAG}
WORKDIR /app
COPY server.rb /app/server.rb
EXPOSE 8080
CMD ["ruby", "/app/server.rb"]
