FROM php:8.1-apache

# Full SuiteCRM tree from salesagility/SuiteCRM @ ${SUITECRM_TAG}.
# Not a ModuleScanner extract / function harness.
ARG SUITECRM_TAG=v7.15.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpng-dev libjpeg-dev libfreetype6-dev libzip-dev libicu-dev \
        libxml2-dev libcurl4-openssl-dev \
        unzip git default-mysql-client curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        gd zip intl xml curl mysqli pdo pdo_mysql bcmath \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

RUN { \
    echo 'upload_max_filesize = 50M'; \
    echo 'post_max_size = 50M'; \
    echo 'memory_limit = 512M'; \
    echo 'max_execution_time = 300'; \
    echo 'error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_NOTICE & ~E_WARNING'; \
    echo 'display_errors = Off'; \
    echo 'log_errors = On'; \
} > /usr/local/etc/php/conf.d/suitecrm.ini

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# php:apache WORKDIR is /var/www/html; deleting it first breaks git's cwd.
RUN mkdir -p /tmp \
    && cd /tmp \
    && rm -rf /var/www/html \
    && GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch ${SUITECRM_TAG} \
        https://github.com/salesagility/SuiteCRM.git /var/www/html \
    && test -f /var/www/html/suitecrm_version.php \
    && test -f /var/www/html/ModuleInstall/ModuleScanner.php \
    && grep -q "suitecrm_version" /var/www/html/suitecrm_version.php

WORKDIR /var/www/html

# Whole-repo composer install (SuiteCRM app), not a sliced scanner package.
# ext-imap is only suggested for the Emails module; Module Loader does not need it.
RUN if [ -f composer.json ]; then \
        COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_MEMORY_LIMIT=-1 composer install \
            --no-dev --no-interaction --prefer-dist --no-progress \
            --ignore-platform-req=ext-imap ; \
    fi

RUN mkdir -p cache custom modules upload/upgrades/module \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 775 cache custom modules upload

RUN sed -i 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf \
    && echo 'ServerName localhost' >> /etc/apache2/apache2.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
