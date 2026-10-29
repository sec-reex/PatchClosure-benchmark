# PatchClosure-Bench recipe for froxlor-cve-2026-41234.
# Real Froxlor built from the REAL git tag (FROXLOR_REF) + MariaDB + Apache/mod_php.
# v0 = 2.3.4  (pre CVE-2026-30932: LOC/RP/SSHFP/TLSA content NOT validated)
# v1 = 2.3.5  (CVE-2026-30932 fix: validateDnsLoc/Rp/Sshfp/Tlsa; TXT records missed) <- target
# v2 = 2.3.7  (CVE-2026-41234 fix: preg_replace strips control chars from ALL content)
FROM php:8.2.29-apache-bookworm

ARG FROXLOR_REF
ENV FROXLOR_REF=${FROXLOR_REF}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip zip libpng-dev libjpeg-dev libfreetype6-dev libzip-dev \
        libicu-dev libxml2-dev libonig-dev libcurl4-openssl-dev libgmp-dev \
        default-mysql-client mariadb-client ca-certificates curl \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli mbstring gd zip intl bcmath posix gmp pcntl \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.7.9 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

# Whole upstream tag tarball (not a raw-file slice). Annotated tags break
# `git clone --depth 1 --branch` under rate-limit / shallow-tag flakes.
RUN curl -fsSL --retry 5 --retry-delay 4 --retry-all-errors \
      "https://github.com/froxlor/froxlor/archive/refs/tags/${FROXLOR_REF}.tar.gz" \
    | tar xz --strip-components=1 \
    && test -f /var/www/html/index.php \
    && COMPOSER_ALLOW_SUPERUSER=1 composer install --no-interaction --no-progress --prefer-dist --no-dev \
    && chown -R www-data:www-data /var/www/html

# Apache must follow symlinks for the DataDump/zone paths used by the gate setup
RUN sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf \
    && sed -ri 's!Options Indexes FollowSymLinks!Options Indexes FollowSymLinks!g' /etc/apache2/apache2.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
