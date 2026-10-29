FROM composer:2 AS deps

ARG OCTOBER_VERSION=1.0.469

WORKDIR /app

# Clone October CMS skeleton at the specific tag.
# Fix composer.json for Composer 2 compatibility: pin exact package versions,
# upgrade merge-plugin, strip require-dev, disable advisory blocking and plugins.
RUN apk add --no-cache jq \
    && git config --global --add safe.directory /app \
    && git clone --depth 1 --branch "v${OCTOBER_VERSION}" \
       https://github.com/octobercms/october.git /app \
    && jq --arg v "${OCTOBER_VERSION}" \
       'del(."require-dev") | del(.scripts) | .require["october/rain"]=$v | .require["october/system"]=$v | .require["october/backend"]=$v | .require["october/cms"]=$v | .require["wikimedia/composer-merge-plugin"]="^2.0" | .config["allow-plugins"]={"*": true} | .config["policy"]={"advisories":{"block": false}}' \
       composer.json > composer.json.tmp \
    && mv composer.json.tmp composer.json

# Install deps without plugins or scripts (avoids Composer 2 plugin blocking).
# Then regenerate autoloader.
RUN COMPOSER_ALLOW_SUPERUSER=1 composer install \
        --no-interaction --no-dev --no-scripts --no-plugins \
        --ignore-platform-reqs --prefer-dist \
    && composer config platform-check false \
    && composer dump-autoload --no-dev --optimize --no-plugins --no-scripts \
    && test -f /app/vendor/october/rain/src/Support/helpers.php

# ---- Runtime stage ----
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpng-dev libjpeg-dev libfreetype6-dev \
        libzip-dev libxml2-dev \
        curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) pdo_mysql gd zip xml \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app /var/www/html
RUN chown -R www-data:www-data /var/www/html

RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' \
        /etc/apache2/apache2.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
