# REAL Concrete CMS, cloned at the exact CVE git tag at build time, installed DB-backed and served
# over HTTP. NO source-lift: the vulnerable concrete/blocks/express_entry_list/controller.php is the
# real cloned file; the object-injection is triggered by an EXTERNAL HTTP request through the real
# Concrete CMS bootstrap. CMS_TAG selects the version (9.4.7 / 9.4.8 / 9.5.1).
FROM php:8.1-apache

# --- system + PHP extensions Concrete CMS requires -------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip default-mysql-client \
        libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev libicu-dev libonig-dev libxml2-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli gd zip intl mbstring exif bcmath opcache \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# --- composer --------------------------------------------------------------------------------------
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# --- clone the REAL Concrete CMS tree at the exact tag + install real dependency graph -------------
# ARG after apt/php-ext so tag changes do not bust the expensive extension compile layer.
WORKDIR /app
ARG CMS_TAG=9.4.8
RUN git clone --depth 1 --branch "${CMS_TAG}" https://github.com/concretecms/concretecms.git /app
ENV COMPOSER_MEMORY_LIMIT=-1
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV COMPOSER_NO_AUDIT=1
RUN set -eux; \
    composer config --global audit.block-insecure false || true; \
    n=0; \
    until [ "$n" -ge 3 ]; do \
      composer install --no-interaction --no-progress --no-dev --optimize-autoloader --ignore-platform-reqs && break; \
      n=$((n+1)); sleep 20; \
    done; \
    [ "$n" -lt 3 ]

# --- writable dirs the installer/runtime need ------------------------------------------------------
RUN mkdir -p application/files packages updates application/config \
    && chown -R www-data:www-data /app \
    && chmod -R 775 application packages updates concrete/config 2>/dev/null || true

# --- apache: serve the Concrete CMS repo root ------------------------------------------------------
ENV APACHE_DOCUMENT_ROOT=/app
RUN sed -ri 's!/var/www/html!/app!g' /etc/apache2/sites-available/000-default.conf /etc/apache2/apache2.conf \
    && printf '<Directory /app>\n  AllowOverride All\n  Require all granted\n</Directory>\n' > /etc/apache2/conf-available/concrete.conf \
    && a2enconf concrete
RUN printf 'memory_limit=512M\nmax_execution_time=120\npost_max_size=32M\nupload_max_filesize=32M\n' > /usr/local/etc/php/conf.d/concrete.ini

# entrypoint: plant the per-run canary OUTSIDE the app dir, install CMS if needed, seed Express+block,
# then run apache. install.sh is mounted at run time.
COPY docker-entrypoint.sh /usr/local/bin/pcb-entrypoint.sh
RUN chmod +x /usr/local/bin/pcb-entrypoint.sh
EXPOSE 80
CMD ["/usr/local/bin/pcb-entrypoint.sh"]
