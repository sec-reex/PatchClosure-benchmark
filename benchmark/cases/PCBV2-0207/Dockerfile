# PatchClosure-Bench recipe for twiki-cve-2009-4898 (CVE-2009-1339 -> CVE-2009-4898).
#
# Runs the REAL published TWiki (Perl/CGI enterprise wiki) under Apache + mod_cgid.
# The version-specific save-CSRF guard that both CVEs touch is executed by TWiki's
# OWN lib/TWiki/UI/Save.pm + lib/TWiki/UI.pm -- NOT reimplemented, NOT lifted.
#
# The real TWiki tarball is fetched from the SourceForge archive at BUILD time
# (nothing but small text files live in this case dir). TWIKI_VER selects the
# release, passed per compose profile:
#   v0 = 4.3.0  (pre-CVE-2009-1339): save has NO CSRF guard  -> forged GET save works.
#   v1 = 4.3.1  (CVE-2009-1339 fix = the CVE-2009-4898 TARGET): save requires POST,
#               NO token  -> forged GET blocked, tokenless forged POST still works.
#   v2 = 4.3.2  (CVE-2009-4898 fix): save requires POST AND a valid one-time crypt
#               token (verifyCryptToken) -> tokenless forged POST blocked.
#
# COMPAT NOTE (portability only, security-neutral): TWiki 4.3.x (2009) uses the
# `foreach $x qw(...)` list-without-parens form and `defined @array`, both made
# fatal by modern Perl (>=5.22). No base image ships a Perl old enough (5.20 and
# below are v1-manifest images Docker 29 refuses to pull), so at build time we
# mechanically wrap those `foreach ... qw(...)` lists in parens and drop the
# `defined` before the array. This is a pure syntax rewrite: it does NOT touch the
# save-CSRF predicates (the post_method_only method check and the CryptToken
# verifyCryptToken gate are left byte-for-byte identical). See repro.log.
FROM debian:bookworm-slim

ARG TWIKI_VER=4.3.2

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 perl libcgi-pm-perl liberror-perl \
      libcgi-session-perl libunicode-string-perl \
      ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# --- fetch the REAL TWiki release (full tarball, not a single module) ----------
# Folder is "TWiki 4.3.x" (space). Underscore form 404s. Fallback = SF mirror CDN.
RUN set -eux; \
    url="https://sourceforge.net/projects/twiki/files/TWiki%20for%20all%20Platforms/TWiki%20${TWIKI_VER}/TWiki-${TWIKI_VER}.tgz/download"; \
    url2="https://downloads.sourceforge.net/project/twiki/TWiki%20for%20all%20Platforms/TWiki%20${TWIKI_VER}/TWiki-${TWIKI_VER}.tgz"; \
    ok=0; \
    for u in "$url" "$url2"; do \
      if curl -fL --retry 5 --retry-delay 4 --max-time 180 "$u" -o /tmp/twiki.tgz \
         && gzip -t /tmp/twiki.tgz; then \
        ok=1; break; \
      fi; \
    done; \
    test "$ok" = 1; \
    mkdir -p /var/www/twiki; \
    tar xzf /tmp/twiki.tgz -C /var/www/twiki; \
    rm -f /tmp/twiki.tgz; \
    chmod a+rx /var/www/twiki/bin/*

WORKDIR /var/www/twiki

# --- security-neutral Perl 5.36 portability rewrite (see COMPAT NOTE) ----------
# Wrap `foreach [my] $x qw(...)` -> `foreach [my] $x (qw(...))` (qw body has no
# nested parens, so the first ')' closes it) and un-`defined` the array in setlib.
RUN set -eux; \
    for f in lib/TWiki/Store.pm lib/TWiki/UI/Save.pm lib/TWiki/Func.pm \
             lib/TWiki/Store/RcsFile.pm lib/CPAN/lib/CGI/Session.pm \
             lib/TWiki/Configure/Load.pm \
             lib/TWiki/Configure/Checkers/BasicSanity.pm; do \
      perl -0777 -i -pe 's/((?:for|foreach)\s+(?:my\s+)?\$\w+\s+)(qw\([^)]*\))/$1($2)/gs' "$f"; \
    done; \
    sed -i 's/if defined \@localPerlLibPath/if \@localPerlLibPath/' bin/setlib.cfg

# --- TWiki site configuration (what bin/configure would write) -----------------
COPY LocalSite.cfg /var/www/twiki/lib/LocalSite.cfg

# --- Apache: serve TWiki bin/ as CGI at /bin, pub/ as static at /pub -----------
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork cgi rewrite \
 && printf 'ServerName localhost\n' >> /etc/apache2/apache2.conf
COPY twiki-apache.conf /etc/apache2/sites-available/000-default.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# PCB_VERSION (v0/v1/v2) and PCB_FLAG are injected by docker-compose.
EXPOSE 80
CMD ["/entrypoint.sh"]
