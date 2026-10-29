FROM php:5.6-apache

# mysqlnd is bundled with this image; no Debian Stretch apt (archives are gone).
RUN docker-php-ext-configure mysql --with-mysql=mysqlnd \
 && docker-php-ext-configure mysqli --with-mysqli=mysqlnd \
 && docker-php-ext-install mysql mysqli

# Official SourceForge full package (html/ overlay for PHP-Nuke 7.0–8.0).
# Build-arg selects 2.5.05 / 2.5.06 / 2.5.07 — the entire html/ tree, not a sliced file.
ARG NS_TGZ=upstream/NukeSentinel_2506_70-80.tar.gz
COPY ${NS_TGZ} /tmp/ns.tgz
RUN set -eux; \
    mkdir -p /tmp/ns /var/www/html; \
    tar xzf /tmp/ns.tgz -C /tmp/ns; \
    HTML="$(find /tmp/ns -type d -name html | head -1)"; \
    test -n "$HTML"; \
    cp -a "$HTML"/. /var/www/html/; \
    test -f /var/www/html/includes/nukesentinel.php; \
    test -f /var/www/html/language/nukesentinel/lang-english.php; \
    rm -rf /tmp/ns /tmp/ns.tgz

# Thin PHP-Nuke host (config + sql_db + front controller). Language/templates come from the tarball.
COPY app/index.php /var/www/html/index.php
COPY app/config.php /var/www/html/config.php
COPY app/db/db.php /var/www/html/db/db.php
COPY app/init.sql /opt/init.sql
COPY app/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R www-data:www-data /var/www/html

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
