# PatchClosure-Bench REAL-HTTP-SERVICE image for phpspreadsheet-phar-wrapper-parseurl-bypass.
#
# A real PHP web service (php:8.2-apache, mod_php) that imports a user-referenced spreadsheet.
# It installs the REAL PhpSpreadsheet at PS_VER (1.30.2 / 1.30.3 / 1.30.5) via composer from
# Packagist, so the load path runs through the genuine File::prohibitWrappers() guard being
# studied. The attacker input arrives over an EXTERNAL HTTP request (POST / path=<phar-url>);
# app.php (served at the document root) hands it to the unmodified Reader\Csv::load().
#
# PHP 8.2 base => the phar wrapper reduces to a benign file-READ primitive (no metadata deser /
# no gadget); the oracle only proves the wrapper reached the loader (the prohibitWrappers bypass).
FROM php:8.2-apache

ARG PS_VER
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip git libzip-dev libonig-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install zip mbstring \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /var/www/html
# ext-gd is a phpspreadsheet platform req but is not exercised by the CSV/phar read path we drive,
# so we skip building it (keeps the image small); ext-zip + ext-mbstring ARE installed above.
# policy.advisories.block=false: we DELIBERATELY install the OLD, advisory-flagged versions
# (1.30.2/1.30.3 are the pre-fix / incomplete-fix targets under study) -- composer would otherwise
# refuse to install a version with a known security advisory.
RUN composer config --global policy.advisories.block false \
 && composer require "phpoffice/phpspreadsheet:${PS_VER}" \
      --no-interaction --no-progress --ignore-platform-req=ext-gd

# app.php becomes the document-root endpoint; build_phar.php plants the per-run benign canary phar.
COPY app.php /var/www/html/index.php
COPY build_phar.php /usr/local/bin/build_phar.php
