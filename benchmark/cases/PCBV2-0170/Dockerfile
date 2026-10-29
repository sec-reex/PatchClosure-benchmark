# Real phpMyFAQ per-version image for phpmyfaq-cve-2026-56396.
#
# Boots the REAL phpMyFAQ web application (PHP 8.3 + Apache/mod_php + MariaDB) at a git tag,
# installed via the REAL web installer (setup/index.php). NO source lift, NO shim: the admin
# API endpoints (overwrite-password / edit / update-rights / configuration/list) are served by
# phpMyFAQ's own Symfony routing exactly as shipped. The authorization-guard differential lives
# entirely in phpMyFAQ's own Api\UserController per tag:
#   PMF_TAG=4.1.2 (v0)  overwritePassword unguarded
#   PMF_TAG=4.1.3 (v1)  overwritePassword guarded (CVE-2026-35671); editUser/updateUserRights open
#   PMF_TAG=4.1.4 (v2)  editUser/updateUserRights guarded too (CVE-2026-56396)
FROM php:8.3-apache

ARG PMF_TAG=4.1.3
ENV PMF_TAG=${PMF_TAG}

# --- PHP extensions phpMyFAQ requires (curl/sodium/xml/fileinfo are already in the base image) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip default-mysql-client \
        libpng-dev libjpeg-dev libfreetype6-dev libzip-dev libicu-dev \
        libonig-dev libxml2-dev libcurl4-openssl-dev libsodium-dev \
 && docker-php-ext-configure gd --with-jpeg --with-freetype \
 && docker-php-ext-install -j"$(nproc)" gd zip intl mysqli pdo_mysql mbstring \
 && a2enmod rewrite headers env \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# --- clone REAL phpMyFAQ at the tag and install its real vendor dependencies ---
RUN git clone --depth 1 --branch "${PMF_TAG}" https://github.com/thorsten/phpMyFAQ.git /opt/phpmyfaq-src
WORKDIR /opt/phpmyfaq-src
RUN COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_PROCESS_TIMEOUT=0 \
    composer install --no-dev --no-interaction --prefer-dist --no-scripts --optimize-autoloader

# writable runtime dirs (installer writes content/core/config/database.php, logs, data)
RUN chown -R www-data:www-data /opt/phpmyfaq-src/phpmyfaq/content \
 && chmod -R 0777 /opt/phpmyfaq-src/phpmyfaq/content

COPY pcb/apache-vhost.conf /etc/apache2/sites-available/000-default.conf
COPY pcb/pcb_common.php /opt/pcb_common.php
COPY pcb/pcb_seed.php   /opt/pcb_seed.php
COPY pcb/pcb_reset.php  /opt/phpmyfaq-src/phpmyfaq/pcb_reset.php
COPY pcb/entrypoint.sh  /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
