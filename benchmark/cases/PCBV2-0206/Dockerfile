# Faithful-core image for the Twig sandbox allow-list membrane (CVE-2024-45411 -> CVE-2026-46638).
# One Dockerfile, one role selected by the TWIG_VERSION build-arg. The guard under test is the REAL,
# published twig/twig for that version (installed via composer), so the harness runs the exact bytes
# of twig/twig 3.13.0 (V0), 3.14.0 (V1) and 3.26.0 (V2).
#
# php:8.2-cli satisfies every version's platform requirement (3.14.0 needs php>=8.0.2; 3.26.0 needs
# php>=8.1.0). No app, no DB -- a tiny built-in-server harness drives one Twig Environment + SecurityPolicy.
FROM php:8.2-cli

ARG TWIG_VERSION=3.14.0
ENV TWIG_VERSION=${TWIG_VERSION}

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Install the exact published twig/twig for this profile. These versions are DELIBERATELY vulnerable
# (that is the whole point of the differential), so Composer 2's advisory-block policy must be turned
# off or it refuses to install them.
RUN composer config --global policy.advisories.block false \
    && composer require "twig/twig:${TWIG_VERSION}" --no-interaction --no-audit --no-progress

COPY harness.php /app/harness.php

EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "/app/harness.php"]
