# Whole TYPO3 6.0 CMS tree at a tagged release (app CVE).
# git clone --branch <tag> of the ENTIRE TYPO3/typo3 repo into the Apache
# docroot. Thin FAL consumer (harness.php) autoloads in-tree
# typo3/sysext/core/Classes — not a Classes-only copy under /opt.
#
#   T3_TAG=TYPO3_6-0-4  (V0) renameFile has NO extension check
#   T3_TAG=TYPO3_6-0-8  (V1) CVE-2013-4250: RAW name checked; trailing-space residual
#   T3_TAG=TYPO3_6-0-9  (V2) CVE-2013-4321: sanitize before check
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG T3_TAG
ENV T3_TAG=${T3_TAG}

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN test -n "$T3_TAG" \
 && git clone --depth 1 --branch "$T3_TAG" https://github.com/TYPO3/typo3.git /var/www/html \
 && rm -rf /var/www/html/.git \
 && test -f /var/www/html/index.php \
 && test -f /var/www/html/typo3/sysext/core/Classes/Resource/ResourceStorage.php \
 && test -d /var/www/html/typo3/sysext/backend \
 && test -d /var/www/html/typo3/sysext/install \
 && test -d /var/www/html/typo3/sysext/cms

COPY harness.php /var/www/html/harness.php
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /var/www/html/uploads \
 && chown -R www-data:www-data /var/www/html

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
