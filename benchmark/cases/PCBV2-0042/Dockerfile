FROM php:7.4-cli
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG SNAPPY_VERSION=1.4.2

# Install wkhtmltopdf (real binary the library wraps) + composer deps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       wkhtmltopdf unzip git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Allow installing versions with known security advisories (this IS the
# vulnerability benchmark — we need the vulnerable versions).
RUN composer config --global policy.advisories.block false

# Install the REAL knplabs/knp-snappy at the pinned version.
# PatchClosure: --prefer-dist pulls zipballs from api.github.com via php-curl, whose bullseye
# openssl-1.1.1 TLS1.3 ClientHello this host's gateway resets (curl error 35 SSL_ERROR_SYSCALL).
# --prefer-source git-clones each package instead (git's handshake is not reset); same pinned code.
RUN composer require "knplabs/knp-snappy:${SNAPPY_VERSION}" \
    --no-interaction --prefer-source

# Copy the benchmark app (tiny HTTP service + benign gadget + PHAR builder).
COPY app/BenignMarker.php  /app/BenignMarker.php
COPY app/build_phar.php    /app/build_phar.php
COPY app/index.php         /app/index.php

# Build the benign PHAR whose metadata triggers BenignMarker::__wakeup.
RUN php -d phar.readonly=0 /app/build_phar.php

EXPOSE 80

CMD ["php", "-S", "0.0.0.0:80", "-t", "/app"]
