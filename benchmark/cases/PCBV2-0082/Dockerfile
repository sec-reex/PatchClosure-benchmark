# Real-app image for the WWBN/AVideo comment markdown XSS sink (CVE-2026-27568 -> CVE-2026-33500).
#
# NO source-lift: this clones the REAL github.com/WWBN/AVideo tree at the exact CVE commit (AE_REF)
# and serves it. The sink markDownToHTML() + ParsedownSafeWithLinks execute out of the cloned
# objects/functionsSecurity.php over the REAL vendored Parsedown (vendor/erusev/parsedown, committed
# in the repo). avideo_sink.php is thin glue that stores the attacker comment and renders it by
# CALLING the real sink -- it re-implements nothing.
#
# Per-version selection is by the AE_REF build arg:
#   v0 = 3905f03df0f0d05c44715419d7535e4dc3649e76      (pre-CVE-2026-27568: plain Parsedown 1.7.4,
#                                                        safeMode default OFF, no sanitizer -> both
#                                                        raw-HTML and markdown javascript: live)
#   v1 = f154167251c9cf183ce09cd018d07e9352310457      (CVE-2026-27568 fix = TARGET: ParsedownSafeWithLinks
#                                                        sanitizes raw-HTML <a>, but NO inlineLink override
#                                                        -> markdown [x](javascript:) bypasses)
#   v2 = 3ae02fa240939dbefc5949d64f05790fd25d728d       (CVE-2026-33500 fix: adds inlineLink() override
#                                                        applying the same scheme whitelist -> markdown
#                                                        javascript: href blanked)
FROM php:8.3-cli

ARG AE_REF
ENV AE_REF=${AE_REF}

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Clone ONLY the pinned commit of the REAL AVideo repo (shallow) -- no source is copied into this case.
RUN set -eux; \
    git init /app; \
    git -C /app remote add origin https://github.com/WWBN/AVideo.git; \
    git -C /app fetch --depth 1 origin "${AE_REF}"; \
    git -C /app checkout -q FETCH_HEAD; \
    test -f /app/objects/functionsSecurity.php; \
    test -f /app/vendor/erusev/parsedown/Parsedown.php

# Thin real-bootstrap HTTP entry (stores + renders the comment via the REAL cloned sink).
COPY avideo_sink.php /avideo_sink.php

EXPOSE 80
# PHP built-in server: every request is dispatched through the router, which executes the REAL
# cloned AVideo files to reach markDownToHTML().
CMD ["php", "-d", "display_errors=0", "-S", "0.0.0.0:80", "/avideo_sink.php"]
