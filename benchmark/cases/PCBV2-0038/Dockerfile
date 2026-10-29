# PatchClosure-Bench recipe for froxlor-cve-2026-41231.
# Real Froxlor built from the REAL git tag (FROXLOR_REF) + MariaDB + Apache/mod_php.
# v0 = 2.0.11 (pre CVE-2023-6069: FileDir::makeCorrectDir has NO symlink check at all)
# v1 = 2.3.5  (CVE-2023-6069 fix active in FTP/DirOptions/DirProtections/SubDomains;
#              DataDump.add missed -> CVE-2026-41231 open) <- target
# v2 = 2.3.6  (CVE-2026-41231 fix: DataDump.add passes $fixed_homedir to makeCorrectDir)
FROM php:8.2-apache

ARG FROXLOR_REF
ENV FROXLOR_REF=${FROXLOR_REF}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip zip libpng-dev libjpeg-dev libfreetype6-dev libzip-dev \
        libicu-dev libxml2-dev libonig-dev libcurl4-openssl-dev libgmp-dev \
        default-mysql-client mariadb-client ca-certificates \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli mbstring gd zip intl bcmath posix gmp pcntl \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

RUN git clone --depth 1 --branch "${FROXLOR_REF}" https://github.com/froxlor/froxlor.git . \
    && if [ "${FROXLOR_REF}" = "2.0.11" ]; then \
         COMPOSER_ALLOW_SUPERUSER=1 composer update --no-interaction --no-progress --no-dev; \
       else \
         COMPOSER_ALLOW_SUPERUSER=1 composer install --no-interaction --no-progress; \
       fi \
    && chown -R www-data:www-data /var/www/html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
