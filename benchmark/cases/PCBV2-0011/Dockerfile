# PatchClosure-Bench env for drupal-core-cve-2018-7602  (CVE-2018-7600 -> CVE-2018-7602).
# Faithful-core over the PINNED OFFICIAL Drupal image: the real upstream core class that IS the
# patched guard -- \Drupal\Core\Security\RequestSanitizer -- ships inside each tag and is loaded
# via Drupal's own Composer autoloader. The security decision is executed verbatim; only harness.php
# (a benign render-callback sink + the two real attack channels) is added. The V0/V1/V2 differential
# is 100% source-driven by the image tag:
#   DRUPAL_TAG=8.5.0 (V0) -> no RequestSanitizer at all              -> '#'-render keys reach the sink
#   DRUPAL_TAG=8.5.1 (V1) -> CVE-2018-7600 fix: sanitize() strips '#'-keys from GET/POST/COOKIE only,
#                            NEVER inside the 'destination' string  -> destination channel still open  <- TARGET
#   DRUPAL_TAG=8.5.3 (V2) -> CVE-2018-7602 fix: sanitize() adds checkDestination() (UrlHelper::parse
#                            the destination's query + strip '#'-keys) -> destination channel closed
ARG DRUPAL_TAG=8.5.1
FROM drupal:${DRUPAL_TAG}

ARG DRUPAL_TAG=8.5.1
ENV DRUPAL_TAG=${DRUPAL_TAG}

COPY harness.php /var/www/html/harness.php
COPY entrypoint.sh /usr/local/bin/pcb-entrypoint.sh
RUN chmod +x /usr/local/bin/pcb-entrypoint.sh \
 && chown www-data:www-data /var/www/html/harness.php

ENTRYPOINT ["/usr/local/bin/pcb-entrypoint.sh"]
CMD ["apache2-foreground"]
