# PatchClosure-Bench recipe image for wegia-cve-2025-58745 (CVE-2025-22133 -> CVE-2025-58745).
# WeGIA is a PHP web manager for charitable/NGO institutions (LabRedesCefetRJ). The source is
# git-cloned AT BUILD TIME at a per-version tag (recipe-based; no vendored source committed).
#   V0/V1 = WeGIA 3.4.10  (V0 boots with the CVE-2025-22133 finfo Excel-MIME guard NEUTRALISED
#                          to model the pre-CVE-2025-22133 state; V1 = stock 3.4.10, guard present)
#   V2    = WeGIA 3.4.11  (CVE-2025-58745 fix: the controla_xlsx.php upload endpoint is DELETED)
FROM php:8.2-apache

ARG WEGIA_REF=3.4.10

RUN apt-get update && apt-get install -y --no-install-recommends \
      git default-mysql-client ca-certificates curl \
    && docker-php-ext-install -j"$(nproc)" mysqli pdo_mysql \
    && a2enmod rewrite \
    && printf 'default_socket_timeout=3\nmemory_limit=256M\ndisplay_errors=Off\n' > /usr/local/etc/php/conf.d/wegia.ini \
    && rm -rf /var/lib/apt/lists/*

# WeGIA source (recipe): shallow clone the release tag into the docroot at BUILD time.
# The clone is NOT committed to the case dir (removed at teardown); only text stays.
WORKDIR /
RUN rm -rf /var/www/html && GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "${WEGIA_REF}" \
      https://github.com/LabRedesCefetRJ/WeGIA.git /var/www/html \
    && test -f /var/www/html/html/login.php \
    && if [ "${WEGIA_REF}" = "3.4.10" ]; then \
         test -f /var/www/html/html/socio/sistema/controller/controla_xlsx.php; \
       fi \
    && chown -R www-data:www-data /var/www/html
WORKDIR /var/www/html

ENV WEGIA_REF=${WEGIA_REF}

COPY wegia-entrypoint.sh /usr/local/bin/wegia-entrypoint.sh
RUN chmod +x /usr/local/bin/wegia-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/wegia-entrypoint.sh"]
