# Whole Cockpit CMS at a pinned commit (app CVE).
# GitHub archive of the ENTIRE agentejo/cockpit tree into Apache docroot.
# Trigger the product's own proxy: GET /assets/lib/fuc.js.php?url=
# Not a raw ADD of that one file.
#
#   COCKPIT_REF = a5fb51cb... -> V0 (pre-CVE-2017-14611: any scheme)
#   COCKPIT_REF = 0711d4f9... -> V1 (http(s)-only guard; CVE-2018-9302 residual)
#   COCKPIT_REF = 279e6690... -> V2 (proxy file removed upstream)
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG COCKPIT_REF
ENV COCKPIT_REF=${COCKPIT_REF}

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      curl ca-certificates libcurl4-openssl-dev pkg-config \
 && docker-php-ext-install curl \
 && rm -rf /var/lib/apt/lists/*

# PatchClosure: this host's gateway resets the TLS1.3-style ClientHello that bullseye's
# openssl 1.1.1 curl sends by default to github.com (curl: (35) SSL_ERROR_SYSCALL). Pinning
# --tls-max 1.2 reshapes the handshake so it passes; the pinned URL is untouched. (git/openssl3
# are unaffected; this only matters for the bullseye curl fetch.)
RUN test -n "${COCKPIT_REF}" \
 && curl -fsSL --tls-max 1.2 "https://github.com/agentejo/cockpit/archive/${COCKPIT_REF}.tar.gz" -o /tmp/cockpit.tar.gz \
 && mkdir -p /tmp/cockpit \
 && tar xzf /tmp/cockpit.tar.gz -C /tmp/cockpit --strip-components=1 \
 && rm -f /tmp/cockpit.tar.gz \
 && test -f /tmp/cockpit/index.php \
 && test -d /tmp/cockpit/assets \
 && test -d /tmp/cockpit/modules \
 && rm -rf /var/www/html \
 && mv /tmp/cockpit /var/www/html \
 && chown -R www-data:www-data /var/www/html
