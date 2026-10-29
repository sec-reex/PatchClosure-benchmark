# PatchClosure-Bench recipe image for qdpm-cve-2020-7246 (CVE-2015-3884 -> CVE-2020-7246).
# qdPM is a Symfony-1.4 PHP app. The version is downloaded from SourceForge AT BUILD TIME
# (recipe-based: no vendored app source committed). One image per version via QDPM_VER arg.
#   V0/V1 = qdPM 9.1  (V0 boots with the uploads script-block .htaccess neutralised to model
#                      the pre-CVE-2015-3884-mitigation state; V1 = stock 9.1, mitigation present)
#   V2    = qdPM 9.2  (CVE-2020-7246 fix: app::is_image() guards the photo upload + unlink)
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG QDPM_VER=9.1

RUN apt-get update && apt-get install -y --no-install-recommends \
      libpng-dev libjpeg62-turbo-dev libfreetype6-dev default-mysql-client curl unzip ca-certificates \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" gd mysqli pdo_mysql \
    && a2enmod rewrite \
    && printf 'memory_limit=256M\narg_separator.output="&"\n' > /usr/local/etc/php/conf.d/qdpm.ini \
    && printf '<Directory /var/www/html/>\n  AllowOverride All\n  Require all granted\n</Directory>\n' \
       > /etc/apache2/conf-available/qdpm.conf \
    && a2enconf qdpm \
    && rm -rf /var/lib/apt/lists/*

# qdPM source (recipe): the canonical source is SourceForge
#   https://sourceforge.net/projects/qdpm/files/qdPM_${QDPM_VER}.zip/download
# but Docker's build network blackholes SourceForge's mirror (resolves to reserved 198.18/15),
# so the gate pre-fetches the released zip on the host into the build context and COPYs it here.
# The zips are NOT committed (removed at teardown); only text stays in the case dir. Zip root == app root.
COPY qdPM_9.1.zip qdPM_9.2.zip /tmp/
RUN rm -rf /var/www/html && mkdir -p /var/www/html /tmp/qdpm \
    && unzip -q "/tmp/qdPM_${QDPM_VER}.zip" -d /tmp/qdpm \
    && cp -a /tmp/qdpm/. /var/www/html/ \
    && rm -rf /tmp/qdpm /tmp/qdPM_*.zip \
    && chown -R www-data:www-data /var/www/html

ENV QDPM_VER=${QDPM_VER}

COPY qdpm-entrypoint.sh /usr/local/bin/qdpm-entrypoint.sh
RUN chmod +x /usr/local/bin/qdpm-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/qdpm-entrypoint.sh"]
