# Real-library-wrap image for dompdf SVG-image SSRF (CVE-2023-23924 -> CVE-2023-24813).
#
# Installs the REAL composer `dompdf/dompdf:${DOMPDF_VERSION}` bytes (2.0.0 / 2.0.2 / 2.0.3)
# behind a tiny PHP HTTP render service that runs the REAL
#   $dompdf->loadHtml($html); $dompdf->render();
# on attacker-supplied HTML. The HTML embeds an SVG whose inner <image> href points at the
# internal canary sidecar; a genuine SSRF is the real dompdf/php-svg-lib fetching that URL.
#
# DOMPDF_VERSION selects the vulnerability profile at BUILD time (real bytes per version):
#   2.0.0 = V0 : pre-CVE-2023-23924, no SVG inner-image URI validation (SSRF open)
#   2.0.2 = V1 : CVE-2023-23924 fixed (inner-image resolve_url validation), but the
#                empty-xlink:href bypass (CVE-2023-24813) remains  <- TARGET
#   2.0.3 = V2 : CVE-2023-24813 fixed (validates BOTH xlink:href and href)
FROM php:8.1-cli

ARG DOMPDF_VERSION
ENV DOMPDF_VERSION=${DOMPDF_VERSION}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git unzip libpng-dev libjpeg-dev libfreetype6-dev libzip-dev libxml2-dev libonig-dev ca-certificates \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" gd mbstring zip \
 && rm -rf /var/lib/apt/lists/*

# composer 2.6 (pre-advisory-blocking): 2.7+ REFUSES to install versions with known CVE
# advisories, but installing the REAL vulnerable dompdf bytes is exactly the point here.
COPY --from=composer:2.6 /usr/bin/composer /usr/bin/composer

WORKDIR /app
# REAL dompdf bytes for the selected profile. --with-all-dependencies pulls the matching
# real php-svg-lib / php-font-lib that dompdf 2.0.x resolves to (the php-svg-lib parser
# discrepancy is half of the CVE-2023-24813 root cause, so we keep the real transitive deps).
RUN composer require --no-interaction --no-progress --no-audit --with-all-dependencies \
      "dompdf/dompdf:${DOMPDF_VERSION}"

COPY server.php /app/server.php

# Fixed, per-run-random flag is planted at runtime via env by the harness.
EXPOSE 80
CMD ["php", "-d", "allow_url_fopen=On", "-S", "0.0.0.0:80", "/app/server.php"]
