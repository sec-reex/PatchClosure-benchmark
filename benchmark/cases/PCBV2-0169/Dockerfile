# Whole published PHPMailer package from Packagist (library CVE).
# Not a COPY of class.phpmailer.php slices.
#   v0 = 5.2.17  (raw -f%s)
#   v1 = 5.2.18  (CVE-2016-10033: escapeshellarg)
#   v2 = 5.2.20  (CVE-2016-10045: isShellSafe)
FROM php:7.4-cli
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends unzip git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG PM_VER=5.2.18
WORKDIR /opt/app
# These PHPMailer 5.2.x releases ARE the CVE targets; Packagist advisories would
# otherwise refuse to install the exact vulnerable versions we need to gate.
# PatchClosure: composer's default dist install downloads a zipball from api.github.com via
# php-curl, whose bullseye openssl-1.1.1 TLS1.3 ClientHello this host's gateway resets
# (curl error 35 SSL_ERROR_SYSCALL). --prefer-source makes composer git-clone the pinned tag
# instead (git's handshake is not reset); same vendored source, no URL/version change.
RUN composer require "phpmailer/phpmailer:${PM_VER}" --no-interaction --no-audit --no-progress --no-security-blocking --prefer-source \
 && test -f /opt/app/vendor/phpmailer/phpmailer/class.phpmailer.php \
 && php -r 'require "/opt/app/vendor/autoload.php"; var_export(class_exists("PHPMailer")); echo PHP_EOL;'

COPY sendmail_shim.sh /usr/local/bin/sendmail
RUN chmod +x /usr/local/bin/sendmail \
 && printf 'sendmail_path = /usr/local/bin/sendmail -t -i\n' > /usr/local/etc/php/conf.d/pcb-mail.ini

COPY harness.php /opt/harness.php
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/opt/entrypoint.sh"]
