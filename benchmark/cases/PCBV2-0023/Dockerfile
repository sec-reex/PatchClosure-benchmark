# REAL Admidio (Apache + PHP 8.3 + MySQL) for the SSO-metadata SSRF pair
# CVE-2026-32812 (V1 incomplete fix) -> CVE-2026-42194 (V2 fix).
#
# This boots the REAL Admidio app: git-checks-out the exact per-profile release tag
# (ARG ADMIDIO_VERSION), `composer install`s its real vendor tree, and serves Admidio's OWN
# modules/sso/fetch_metadata.php endpoint. The attacker (oracle.py) logs in as the real admin
# over EXTERNAL HTTP and drives that endpoint; Admidio's own scheme/gethostbyname/IP-filter
# guard and cURL fetch run inside the app. NOTHING is source-lifted.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV APACHE_DOCUMENT_ROOT=/opt/app-root/src

RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 ca-certificates git unzip curl openssl \
      libapache2-mod-php8.3 \
      php8.3-cli php8.3-common php8.3-curl php8.3-gd php8.3-intl php8.3-mbstring \
      php8.3-mysql php8.3-xml php8.3-zip php8.3-bcmath php8.3-gmp php8.3-bz2 \
      php8.3-soap php8.3-ldap \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1
ENV COMPOSER_NO_AUDIT=1

# --- REAL Admidio source at the exact release tag ---
ARG ADMIDIO_VERSION=v5.0.7
RUN git clone --depth 1 --branch "${ADMIDIO_VERSION}" https://github.com/Admidio/admidio "${APACHE_DOCUMENT_ROOT}"
WORKDIR ${APACHE_DOCUMENT_ROOT}
RUN composer install --no-interaction --no-progress --no-dev \
 && printf '%s' "${ADMIDIO_VERSION}" > /opt/app-root/.admidio_version

# --- Trust the PCB test CA so cURL/openssl peer-verify the HTTPS SSRF sidecars ---
COPY certs/ca.crt /usr/local/share/ca-certificates/pcb-test-ca.crt
RUN update-ca-certificates
# Point PHP's cURL + openssl streams explicitly at the system bundle (belt-and-suspenders).
RUN { \
      echo "curl.cainfo=/etc/ssl/certs/ca-certificates.crt"; \
      echo "openssl.cafile=/etc/ssl/certs/ca-certificates.crt"; \
      echo "allow_url_fopen=On"; \
    } > /etc/php/8.3/apache2/conf.d/99-pcb.ini \
 && cp /etc/php/8.3/apache2/conf.d/99-pcb.ini /etc/php/8.3/cli/conf.d/99-pcb.ini

# --- Apache: docroot + Listen 8080 ---
RUN a2enmod php8.3 rewrite \
 && sed -ri -e "s!/var/www/html!${APACHE_DOCUMENT_ROOT}!g" /etc/apache2/sites-available/*.conf \
 && sed -ri -e "s!/var/www/!${APACHE_DOCUMENT_ROOT}!g" /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
 && sed -ri -e "s/^Listen 80$/Listen 8080/" /etc/apache2/ports.conf \
 && sed -ri -e "s/<VirtualHost \*:80>/<VirtualHost *:8080>/" /etc/apache2/sites-available/000-default.conf \
 && sed -ri -e "s|^ErrorLog .*$|ErrorLog /dev/stderr|" /etc/apache2/apache2.conf

RUN chown -R www-data:www-data "${APACHE_DOCUMENT_ROOT}/adm_my_files"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
