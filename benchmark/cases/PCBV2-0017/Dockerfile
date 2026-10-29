# Faithful-core Puma env for PatchClosure-Bench puma-cve-2020-5249.
# NOTE: puma 4.3.2 and 3.12.3 (the CVE-2020-5247 security releases) were YANKED
# from rubygems, so we build each version from its immutable git TAG instead:
#   V0 = v4.3.1 (pre CVE-2020-5247, fully vulnerable)
#   V1 = v4.3.2 (CVE-2020-5247 patched = TARGET; early-hints sink still unchecked)
#   V2 = v4.3.3 (CVE-2020-5249 patched = complete)
# A tiny Rack app reflects a request param into (a) a regular response header and
# (b) an early-hints header. Puma runs directly (no Rails).
FROM ruby:2.7-slim

## Debian bullseye is EOL: repoint security repo at the archive before apt runs.
RUN printf 'deb http://archive.debian.org/debian bullseye main\ndeb http://archive.debian.org/debian bullseye-updates main\n' > /etc/apt/sources.list
RUN apt-get update -o Acquire::Check-Valid-Until=false \
    && apt-get install -y --no-install-recommends build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY config.ru /app/config.ru
COPY puma_config.rb /app/puma_config.rb

ARG PUMA_REF
RUN printf "source 'https://rubygems.org'\ngem 'puma', git: 'https://github.com/puma/puma.git', tag: '%s'\n" "${PUMA_REF}" > /app/Gemfile \
    && bundle install

EXPOSE 9292
# early_hints is enabled in puma_config.rb (the residual sink)
CMD ["sh", "-c", "bundle exec puma -C /app/puma_config.rb /app/config.ru"]
