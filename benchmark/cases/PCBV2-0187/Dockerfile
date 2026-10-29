# REAL Ruby on Rails (2007 stack) for PatchClosure-Bench ruby-on-rails-cve-2007-6077.
#
# Base = Debian Lenny (EOL archive), which ships the era-correct Ruby 1.8 + RubyGems.
# The actual Rails gem for the profile's version (v0=1.2.3, v1=1.2.4, v2=1.2.6) is
# installed from vendored .gem files (rubygems.org's TLS is too new for Ruby 1.8, so the
# gems are vendored, not fetched at build time). The app boots the REAL railties
# DispatchServlet -> Dispatcher -> ActionController::CgiRequest, so the CVE-2007-5380
# :cookie_only guard and the CVE-2007-6077 shared-constant residual run in the real
# actionpack cgi_process.rb. Nothing is lifted.
#
# amd64 base under emulation on arm64 hosts (no arm64 build of a 2007 distro exists).
FROM --platform=linux/amd64 debian/eol:lenny

# Point apt at the Debian archive (Lenny is long past its release date).
RUN set -eux; \
    printf 'deb http://archive.debian.org/debian/ lenny main\n' > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends ruby1.8 rubygems libopenssl-ruby1.8; \
    ln -sf /usr/bin/ruby1.8 /usr/local/bin/ruby; \
    ( ln -sf /usr/bin/gem1.8 /usr/local/bin/gem || true ); \
    rm -rf /var/lib/apt/lists/*

# Shared dependency (rake) -- same layer for every version so it caches once.
COPY vendor/gems/common /gems-common
RUN gem install --local --ignore-dependencies --no-ri --no-rdoc /gems-common/rake-0.8.7.gem

# Per-version real Rails gemset (rails + actionpack + activesupport + the deps the rails
# meta-gem declares, so `gem 'rails'` activates cleanly).
ARG VER=v1
COPY vendor/gems/${VER} /gems
RUN for g in activesupport activerecord actionpack actionmailer actionwebservice rails; do \
        gem install --local --ignore-dependencies --no-ri --no-rdoc /gems/$g-*.gem; \
    done

WORKDIR /app
COPY railsapp /app
RUN chmod -R a+rwX /app/log /app/tmp

ENV PCB_PORT=8080 RAILS_ENV=production
EXPOSE 8080
CMD ["ruby", "/app/boot_server.rb"]
