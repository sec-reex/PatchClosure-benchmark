# PatchClosure-Bench env for wordpress-wp-super-cache-plugin-cve-2013-2011
#   (CVE-2013-2009 -> CVE-2013-2011, WP Super Cache mfunc/mclude PHP code injection into cache).
# Faithful-core: the REAL WP Super Cache plugin source for the pinned version is fetched at build
# from the official wordpress.org SVN tag zip; harness.php executes the version's REAL
# no_mfunc_in_comments() guard + the REAL wp-cache-phase2.php mfunc->PHP cache-generation sink
# verbatim (see harness.php). The version differential is 100% source-driven:
#   WPSC_VERSION=1.2    (V0) -> no no_mfunc_in_comments guard        -> single-comment mfunc executes (CVE-2013-2009)
#   WPSC_VERSION=1.3.1  (V1) -> CVE-2013-2009 guard (open+close regex) -> single-comment blocked; split multi-comment survives (CVE-2013-2011 residual)  <- TARGET
#   WPSC_VERSION=1.3.2  (V2) -> CVE-2013-2011 fix (opening-tag regex)   -> split multi-comment blocked
FROM php:8.2-apache

ARG WPSC_VERSION
ENV WPSC_VERSION=${WPSC_VERSION}
ENV WPSC_DIR=/opt/wpsc

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*

# Fetch ONLY the tagged upstream plugin and keep the two real files the harness executes.
RUN curl -fsSL -o /tmp/wpsc.zip "https://downloads.wordpress.org/plugin/wp-super-cache.${WPSC_VERSION}.zip" \
 && unzip -q /tmp/wpsc.zip -d /tmp/wpsc \
 && mkdir -p /opt/wpsc \
 && cp /tmp/wpsc/wp-super-cache/wp-cache.php        /opt/wpsc/wp-cache.php \
 && cp /tmp/wpsc/wp-super-cache/wp-cache-phase2.php /opt/wpsc/wp-cache-phase2.php \
 && rm -rf /tmp/wpsc /tmp/wpsc.zip

COPY harness.php /var/www/html/harness.php
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R www-data:www-data /var/www/html

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
