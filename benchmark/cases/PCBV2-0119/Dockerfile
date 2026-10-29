# GLPI on PHP 7.4 (the exploit for CVE-2024-31456 is documented to require PHP 7.4).
# Source = official GLPI release tarball pinned by GLPI_VER (whole product, not a Search.php slice).
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libpng-dev libjpeg-dev libfreetype6-dev libicu-dev libzip-dev libbz2-dev \
        libonig-dev libxml2-dev libldap2-dev default-mysql-client curl ca-certificates; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    debMultiarch="$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"; \
    docker-php-ext-configure ldap --with-libdir="lib/${debMultiarch}"; \
    docker-php-ext-install -j"$(nproc)" gd intl zip bz2 exif opcache mysqli mbstring ldap; \
    rm -rf /var/lib/apt/lists/*

ARG GLPI_VER=10.0.14

# Unpack the official release tarball into the docroot. fetch_source.sh places it in ./srccache.
COPY srccache/glpi-${GLPI_VER}.tgz /tmp/glpi.tgz
RUN set -eux; \
    tar -xzf /tmp/glpi.tgz -C /tmp; \
    rm -rf /var/www/html; \
    mv /tmp/glpi /var/www/html; \
    rm -f /tmp/glpi.tgz; \
    chown -R www-data:www-data /var/www/html

RUN a2enmod rewrite && sed -ri 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

RUN { \
      echo 'memory_limit=512M'; \
      echo 'max_execution_time=120'; \
      echo 'session.cookie_httponly=On'; \
      echo 'display_errors=Off'; \
    } > /usr/local/etc/php/conf.d/glpi.ini

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
