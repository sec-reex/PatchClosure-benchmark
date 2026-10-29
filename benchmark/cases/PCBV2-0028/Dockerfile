# REAL TestLink app image for the index.php reqURI reflected-XSS sink
# (CVE-2019-19491 -> CVE-2019-20381). The published TestLink source is CLONED AT BUILD TIME from
# github.com/TestLinkOpenSourceTRMS/testlink-code and checked out at the exact ref for this version
# (TL_REF); NO TestLink tree is committed to the case dir. index.php::initEnv() (the REAL reqURI
# sanity check) reflects reqURI into the REAL gui/templates/tl-classic/main.tpl:25 <iframe src>.
#   v0 = tag 1.9.19          : no javascript guard.
#   v1 = commit e2bebf684    : contains CVE-2019-19491 fix 0e3e90799 -> case-SENSITIVE strpos (TARGET).
#   v2 = tag 1.9.20 (cde6928): CVE-2019-20381 fix -> case-INSENSITIVE stripos.
FROM php:7.4-apache
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG TL_REF
ENV TL_REF=${TL_REF}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git default-mysql-client \
        libpng-dev libjpeg-dev libfreetype6-dev libonig-dev libxml2-dev ca-certificates \
    && docker-php-ext-configure gd --with-jpeg --with-freetype \
    && docker-php-ext-install -j"$(nproc)" mysqli gd mbstring \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Clone the REAL published TestLink at this version's exact ref (no source-lift; real code runs).
# TL_REF may be a tag (1.9.19 / 1.9.20) OR a commit SHA (v1). `git clone --branch` only
# accepts tags/branches, so init+fetch+checkout is required for the SHA.
RUN set -eux; \
    mkdir -p /tmp/tl; \
    git -C /tmp/tl init -q; \
    git -C /tmp/tl remote add origin https://github.com/TestLinkOpenSourceTRMS/testlink-code.git; \
    if ! git -C /tmp/tl fetch --depth 1 origin "${TL_REF}"; then \
      git -C /tmp/tl fetch origin "${TL_REF}"; \
    fi; \
    git -C /tmp/tl checkout --force FETCH_HEAD; \
    git -C /tmp/tl clean -qdfx; \
    rm -rf /tmp/tl/.git; \
    rm -rf /var/www/html && cp -a /tmp/tl /var/www/html; \
    rm -rf /tmp/tl; \
    chown -R www-data:www-data /var/www/html

# TestLink writes compiled Smarty templates + logs at runtime; make those writable.
ENV TESTLINK_LOG_PATH=/var/testlink/logs/
RUN mkdir -p /var/testlink/logs \
    && chmod -R 0777 /var/testlink /var/www/html/gui/templates_c /var/www/html/upload_area \
       /var/www/html/logs 2>/dev/null; true

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
