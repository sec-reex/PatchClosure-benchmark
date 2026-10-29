# Real FreeScout (Laravel help desk) from the FULL upstream tree at tag FS_REF.
# Build context is populated by start.sh (host git tree or GitHub tag tarball) —
# COPY of the whole product, not a sliced Helper.php / stripDangerousTags harness.
FROM php:7.4-apache

# PatchClosure: php:7.4-apache is Debian bullseye (EOL); its deb/security pool was purged from
# the mirrors (apt 404 at build). Redirect to archive.debian.org. Guarded so non-bullseye is untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip zip libpng-dev libjpeg-dev libfreetype6-dev libzip-dev \
        libicu-dev libxml2-dev libonig-dev libc-client-dev libkrb5-dev \
        default-mysql-client ca-certificates \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql mysqli mbstring gd zip intl bcmath imap soap \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/*

# Composer 2.2 LTS still runs on PHP 7.4 (composer:2 latest needs PHP 8+).
COPY --from=composer:2.2 /usr/bin/composer /usr/bin/composer

RUN sed -ri 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/000-default.conf /etc/apache2/apache2.conf \
    && printf '<Directory /var/www/html/public>\n  AllowOverride All\n  Require all granted\n</Directory>\n' > /etc/apache2/conf-available/freescout.conf \
    && a2enconf freescout

WORKDIR /var/www/html

ARG FS_REF
ENV FS_REF=${FS_REF}

# Full FreeScout tree (artisan, app/, composer.json, public/, …).
# PatchClosure: .build_src/ (staged by fetch_source.sh+start.sh) is never produced by runner/gate.sh,
# so clone the pinned tag directly keyed on the per-profile FS_REF build arg. git (installed above),
# not curl — this host resets the bullseye openssl-1.1.1 TLS hello to github, but git is fine.
RUN git clone --depth 1 --branch "${FS_REF}" \
        https://github.com/freescout-help-desk/freescout.git /tmp/fs \
    && cp -a /tmp/fs/. /var/www/html/ \
    && rm -rf /tmp/fs

# PatchClosure: install in two passes. (1) download packages WITHOUT autoloader generation (the
# rap2hpoutre/laravel-log-viewer package ships no src/controllers dir, so autoloader classmap-scan
# would abort). (2) create that dir, then a FULL install to pull any remaining deps (incl. the
# require-dev fzaninotto/faker that freescout's DatabaseServiceProvider needs for seeding) AND
# generate the autoloader. The old single chain ended in `|| true`, which masked a composer failure
# that left faker's src/ absent -> "Class 'Faker\Factory' not found" -> pcb_seed.php seeded nothing
# -> oracle KeyError 'mailbox'. Do NOT mask composer errors.
# --prefer-source: composer's default dist download pulls zipballs from codeload.github.com, whose
# TLS1.3 ClientHello this host's gateway resets for bullseye openssl-1.1.1 (so fzaninotto/faker and
# other github-hosted deps silently fail to download during build -> Faker\Factory missing). Git's
# handshake is NOT reset, so --prefer-source git-clones each dep and completes.
RUN COMPOSER_ALLOW_SUPERUSER=1 composer install --no-interaction --no-progress --no-autoloader --prefer-source
RUN mkdir -p vendor/rap2hpoutre/laravel-log-viewer/src/controllers \
    && COMPOSER_ALLOW_SUPERUSER=1 composer install --no-interaction --no-progress --prefer-source
RUN chown -R www-data:www-data /var/www/html && { cp .env.example .env || true; }

COPY entrypoint.sh /entrypoint.sh
COPY seed.php /var/www/html/pcb_seed.php
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
