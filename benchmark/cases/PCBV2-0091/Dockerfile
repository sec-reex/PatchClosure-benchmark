# REAL Craft CMS (PHP 8.3 + MySQL) for the GraphQL Asset-upload SSRF pair
# CVE-2025-68437 (V1 incomplete) -> CVE-2026-27129 (V2 fix).
#
# This boots the REAL Craft app: composer-installs craftcms/cms pinned to the
# per-profile version (ARG CRAFT_VERSION), runs the real `php craft install`, and
# serves Craft's OWN GraphQL endpoint. The attacker drives Craft's real
# `save_<Volume>_Asset` mutation ( _file.url ) over EXTERNAL HTTP; Craft's own
# validateHostname()/handleUpload() (the CVE-2025-68437 fix, and on V2 the
# CVE-2026-27129 validateIp IPv6-prefix block) run inside the app. NOTHING is
# source-lifted (the prior harness.php lift is RETIRED; the file is left in the
# case dir only for provenance and is no longer built or served).
# php -S (cli) RSTs / dies under Craft GraphQL bootstrap; Apache stays up.
# Readiness is GraphQL { ping } only — Apache 404 is NOT ready.
FROM php:8.3-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git unzip libcurl4-openssl-dev libzip-dev libicu-dev libonig-dev \
      libpng-dev libjpeg62-turbo-dev libfreetype6-dev libwebp-dev \
      default-mysql-client ca-certificates \
 && docker-php-ext-configure gd --with-jpeg --with-freetype --with-webp \
 && docker-php-ext-install -j"$(nproc)" pdo_mysql curl gd intl zip bcmath mbstring \
 && a2enmod rewrite \
 && printf '%s\n' \
      'memory_limit=512M' \
      'max_execution_time=120' \
      'variables_order=EGPCS' \
      > /usr/local/etc/php/conf.d/zz-craft.ini \
 && sed -ri 's!/var/www/html!/app/web!g' /etc/apache2/sites-available/*.conf /etc/apache2/apache2.conf \
 && printf '%s\n' \
      '<Directory /app/web>' \
      '  Options FollowSymLinks' \
      '  AllowOverride All' \
      '  Require all granted' \
      '</Directory>' \
      'ServerName localhost' \
      > /etc/apache2/conf-available/craft-docroot.conf \
 && a2enconf craft-docroot \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV COMPOSER_NO_AUDIT=1
WORKDIR /app

# Real Craft starter project, then pin craftcms/cms to the exact per-profile version.
# NOTE: the vulnerable target versions (5.8.20/5.8.22) are — by design — flagged by Packagist
# security advisories (they ARE the CVE-affected releases we are studying), so we disable the
# advisory *install block* to allow pinning them. This installs the REAL Craft app.
ARG CRAFT_VERSION=5.8.22
# --no-blocking is not on every composer:2 tag; disable advisory *block* via config
# and retry create-project (packagist flakes). Destination /app is created by WORKDIR.
RUN set -eux; \
    composer config --global audit.block-insecure false || true; \
    n=0; \
    until [ "$n" -ge 3 ]; do \
      composer create-project craftcms/craft:5.8.0 /app --no-interaction --no-progress --no-scripts --no-dev && break; \
      n=$((n+1)); sleep 20; \
    done; \
    [ "$n" -lt 3 ]; \
    composer require "craftcms/cms:${CRAFT_VERSION}" --no-interaction --no-progress --no-scripts --no-audit -W; \
    php -r 'require "/app/vendor/autoload.php"; echo "INSTALLED craftcms/cms => ".\Composer\InstalledVersions::getPrettyVersion("craftcms/cms").PHP_EOL;'

COPY pcb_setup.php /app/pcb_setup.php
COPY craft-entrypoint.sh /craft-entrypoint.sh
RUN chmod +x /craft-entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/craft-entrypoint.sh"]
