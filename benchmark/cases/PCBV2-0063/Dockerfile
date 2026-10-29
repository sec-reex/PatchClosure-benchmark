# Real Cacti installation for cacti-cve-2025-24368 (CVE-2024-31460 -> CVE-2025-24368).
# NOT a source lift: git clone of the real Cacti at the specified release tag,
# Apache + PHP + MariaDB client, running the real Cacti codebase with real MariaDB.
# pcb_probe.php bootstraps Cacti's own environment and calls its own lib/api_automation.php
# functions in-place (never copies them).
FROM php:8.1-apache

ARG CACTI_TAG=release/1.2.27

# System packages for Cacti's PHP extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-mysql-client \
    libmariadb-dev \
    rrdtool librrd-dev \
    libsnmp-dev snmp \
    libldap2-dev \
    libfreetype6-dev libjpeg62-turbo-dev libpng-dev \
    libgmp-dev \
    libicu-dev \
    libxml2-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# PHP extensions required by Cacti
RUN docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install -j$(nproc) \
        mysqli pdo_mysql \
        snmp ldap \
        gd gmp \
        posix sockets \
        intl gettext \
        xml

# Apache modules
RUN a2enmod rewrite headers

# PHP configuration for Cacti
RUN { \
    echo "date.timezone = UTC"; \
    echo "memory_limit = 512M"; \
    echo "max_execution_time = 120"; \
    echo "max_input_vars = 5000"; \
    echo "error_reporting = E_ALL & ~E_STRICT & ~E_DEPRECATED & ~E_NOTICE"; \
    echo "display_errors = Off"; \
    echo "log_errors = On"; \
} > /usr/local/etc/php/conf.d/cacti.ini

# Clone the REAL Cacti at the specified version tag
RUN git clone --depth 1 --branch ${CACTI_TAG} https://github.com/Cacti/cacti.git /var/www/html/cacti && \
    chown -R www-data:www-data /var/www/html/cacti && \
    mkdir -p /var/www/html/cacti/log /var/www/html/cacti/cache/boost \
             /var/www/html/cacti/cache/mibcache /var/www/html/cacti/cache/realtime \
             /var/www/html/cacti/cache/spikekill && \
    chown -R www-data:www-data /var/www/html/cacti/log /var/www/html/cacti/cache

# Set Apache DocumentRoot to the Cacti directory
RUN sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/cacti|g' \
    /etc/apache2/sites-available/000-default.conf && \
    printf '<Directory /var/www/html/cacti>\n\
    Options FollowSymLinks\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>\n' >> /etc/apache2/apache2.conf

# Copy probe endpoint (NOT a source lift; bootstraps REAL Cacti env in-place)
COPY pcb_probe.php /var/www/html/cacti/pcb_probe.php
RUN chown www-data:www-data /var/www/html/cacti/pcb_probe.php

# Entrypoint: waits for MariaDB, imports schema, seeds data, starts Apache
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
