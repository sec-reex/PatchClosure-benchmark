# Real GNU Bash 4.3 at three official patchlevels + real Apache prefork + mod_cgi.
# Sources: ftp.gnu.org / mirrors.kernel.org (bash-4.3.tar.gz + bash-4.3-patches).
#   /opt/bash-v0/bash = 4.3 + 001..024  (CVE-2014-6271 vulnerable)
#   /opt/bash-v1/bash = 4.3 + 001..025  (6271 patched, 7169 still open)
#   /opt/bash-v2/bash = 4.3 + 001..027  (7169 closed)
# Do not slice variables.c / parse.y into a harness.
FROM debian:bullseye-slim AS build
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make patch wget ca-certificates libc6-dev bison \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Prefer kernel.org; fall back to ftp.gnu.org.
RUN set -eux; \
    for base in \
      https://mirrors.kernel.org/gnu/bash \
      https://ftp.gnu.org/gnu/bash; do \
      if wget -q -O bash-4.3.tar.gz "$base/bash-4.3.tar.gz"; then \
        echo "$base" > /tmp/bash-mirror; \
        break; \
      fi; \
    done; \
    test -s bash-4.3.tar.gz; \
    tar xzf bash-4.3.tar.gz
RUN set -eux; \
    MIRROR="$(cat /tmp/bash-mirror)"; \
    mkdir -p patches; \
    for i in $(seq 1 27); do \
      n="$(printf '%03d' "$i")"; \
      wget -q -O "patches/bash43-$n" "$MIRROR/bash-4.3-patches/bash43-$n"; \
    done
WORKDIR /src/bash-4.3
RUN set -eux; \
    for i in $(seq 1 24); do \
      n="$(printf '%03d' "$i")"; \
      patch -p0 < "../patches/bash43-$n"; \
    done
RUN ./configure --without-bash-malloc \
    && make -j"$(nproc)" \
    && mkdir -p /out && cp bash /out/bash-v0
RUN patch -p0 < ../patches/bash43-025 \
    && make -j"$(nproc)" && cp bash /out/bash-v1
RUN patch -p0 < ../patches/bash43-026 && patch -p0 < ../patches/bash43-027 \
    && make -j"$(nproc)" && cp bash /out/bash-v2

FROM debian:bullseye-slim
# PatchClosure: Debian bullseye is EOL; redirect apt to archive.debian.org (runtime stage too).
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/bash-v0 /opt/bash-v0/bash
COPY --from=build /out/bash-v1 /opt/bash-v1/bash
COPY --from=build /out/bash-v2 /opt/bash-v2/bash
RUN chmod +x /opt/bash-v0/bash /opt/bash-v1/bash /opt/bash-v2/bash
# mod_cgi needs prefork (not event/worker).
RUN a2dismod mpm_event >/dev/null 2>&1 || true; \
    a2enmod mpm_prefork >/dev/null 2>&1; \
    a2enmod cgi >/dev/null 2>&1; \
    a2enconf serve-cgi-bin >/dev/null 2>&1 || true
COPY cgi/status.cgi /usr/lib/cgi-bin/status.cgi
RUN chmod 755 /usr/lib/cgi-bin/status.cgi \
    && mkdir -p /var/www/html/leaks \
    && chmod 777 /var/www/html/leaks
EXPOSE 80
