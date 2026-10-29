# Real Pheditor: whole official git-tag tree on php:8.2-apache.
# Source is staged by fetch_source.sh + start.sh into .build_src/ (full repo, not a sliced handler).
FROM php:8.2-apache
ARG PHEDITOR_TAG=2.0.3
# PatchClosure: .build_src/ (staged by fetch_source.sh+start.sh) is never produced by runner/gate.sh,
# so revert to case.json's documented "git clone at build" recipe, keyed on the per-profile
# PHEDITOR_TAG. php:8.2-apache has no git -> install it. git (not curl) avoids this host's
# bullseye-openssl github TLS reset.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite
RUN git clone --depth 1 --branch "${PHEDITOR_TAG}" \
        https://github.com/pheditor/pheditor.git /var/www/html/pheditor \
    && test -f /var/www/html/pheditor/pheditor.php \
    && chown -R www-data:www-data /var/www/html/pheditor
EXPOSE 80
