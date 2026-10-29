# Real Grav CMS image for the cleanDangerousTwig regex SSTI benchmark
# (CVE-2024-28116 -> CVE-2025-66294).
#
# Builds the REAL Grav CMS from the getgrav/grav git tag.  The per-version
# Security::cleanDangerousTwig() runs inside Grav's own Twig::processString()
# -- nothing is lifted.  A thin Grav plugin (pcb-probe) provides a POST
# /pcb-probe endpoint that feeds the submitted Twig payload through
# processString, exercising the real sanitiser+render pipeline.
#
# Build-arg GRAV_TAG selects the version:
#   v0 = 1.7.44  (no cleanDangerousTwig)
#   v1 = 1.7.45  (CVE-2024-28116 fix: single-pass regex blocklist)
#   v2 = 1.8.0-beta.27  (CVE-2025-66294 fix: 4-pass filter)
FROM php:8.3-apache

ARG GRAV_TAG=1.7.45

# ---- PHP extensions required by Grav ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip git libzip-dev libyaml-dev libpng-dev libicu-dev libonig-dev \
    && docker-php-ext-install zip gd opcache intl mbstring \
    && pecl install yaml && docker-php-ext-enable yaml \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Apache: let .htaccess work (Grav needs mod_rewrite)
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/g' \
        /etc/apache2/apache2.conf

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# ---- Clone Grav at the exact version tag ----
RUN git clone --depth 1 --branch ${GRAV_TAG} https://github.com/getgrav/grav.git /tmp/grav \
    && cp -a /tmp/grav/. /var/www/html/ \
    && rm -rf /tmp/grav \
    && git config --global --add safe.directory /var/www/html

WORKDIR /var/www/html

# ---- Install PHP dependencies ----
# COMPOSER_NO_BLOCKING=1 skips advisory-based blocks (twig 1.44 is EOL).
# For V2 (twig 3.x-dev), inject minimum-stability into the project composer.json.
ENV COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_BLOCKING=1
RUN php -r "\$j=json_decode(file_get_contents('composer.json'),true);\$j['minimum-stability']='dev';\$j['prefer-stable']=true;file_put_contents('composer.json',json_encode(\$j,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));" \
    && composer install --no-dev --no-interaction --no-progress 2>&1; \
    test -f vendor/autoload.php || { echo "FATAL: composer install failed"; exit 1; }

# ---- Create working directories Grav needs at runtime ----
RUN mkdir -p cache logs tmp backup images user/config user/pages user/data

# ---- Minimal theme (just renders page.content, no external assets) ----
RUN mkdir -p user/themes/pcb/templates \
    && printf 'name: PCB\nslug: pcb\ntype: theme\nversion: 1.0.0\ndescription: Minimal benchmark theme\nauthor:\n  name: PCB\n' \
       > user/themes/pcb/blueprints.yaml \
    && printf 'enabled: true\n' > user/themes/pcb/pcb.yaml \
    && printf '{{ page.content|raw }}\n' > user/themes/pcb/templates/default.html.twig

# ---- PCB probe plugin ----
COPY pcb-probe.php user/plugins/pcb-probe/pcb-probe.php
RUN printf 'name: PCB Probe\nslug: pcb-probe\ntype: plugin\nversion: 1.0.0\ndescription: Benchmark probe\nauthor:\n  name: PCB\n' \
      > user/plugins/pcb-probe/blueprints.yaml \
    && printf 'enabled: true\n' > user/plugins/pcb-probe/pcb-probe.yaml

# ---- Grav configuration ----
# Use our theme; enable Twig processing; disable undefined_functions so the
# getenv canary callback fires (the default "true" pre-empts user callbacks
# with empty stubs -- that is a separate defence, not cleanDangerousTwig).
RUN printf 'pages:\n  theme: pcb\n  process:\n    twig: true\n    markdown: true\n  twig_first: true\ntwig:\n  undefined_functions: false\n  undefined_filters: false\n  cache: false\n  debug: false\n  autoescape: false\n' \
      > user/config/system.yaml

# Suppress Twig 1.x deprecation noise on PHP 8.x
RUN printf 'error_reporting = E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING & ~E_USER_DEPRECATED\ndisplay_errors = Off\nlog_errors = On\n' \
      > /usr/local/etc/php/conf.d/pcb.ini

# ---- Default home page (readiness signal) ----
RUN mkdir -p user/pages/01.home \
    && printf -- '---\ntitle: Home\n---\nGrav PCB probe ready.\n' > user/pages/01.home/default.md

# ---- Permissions ----
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
CMD ["apache2-foreground"]
