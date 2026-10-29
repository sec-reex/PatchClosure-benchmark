# PatchClosure-Bench recipe for majordomo-2-cve-2011-0063
# (CVE-2011-0049 -> CVE-2011-0063, Majordomo 2 `help` directory traversal).
#
# Recipe-based: NO committed source/images. The Majordomo 2 snapshot is
# fetched at BUILD time from the official archive (ftp.mj2.org) at a pinned
# date, selected per profile by build-arg MJ_URL. Only small text config
# overlays live in this case dir.
#
#   v0 = 20110120 -> NO `..` stripping at all       (vulnerable to CVE-2011-0049)
#   v1 = 20110203 -> `$file =~ s!/?\.\./?!!g;`       (CVE-2011-0049 INCOMPLETE fix;
#                    still traversable via a `./.../` sequence == CVE-2011-0063)  <- TARGET
#   v2 = 20110204 -> `$file =~ s!\.\.!!g;`           (CVE-2011-0063 fixed)
#
# The traversal sink is _list_file_get() in lib/Majordomo.pm, reached through
# the web `help` command:  mj_wwwusr?func=help&extra=<path>. The canary is
# planted OUTSIDE Majordomo's served roots at /pcb_canary/flag by the compose
# entrypoint (from ${PCB_FLAG}); no Majordomo code is modified.
FROM debian:bullseye-slim
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

# Full tarball URL for this profile's snapshot (compose passes it per service).
# Default points at the real upstream archive so the recipe reproduces on any
# host with outbound HTTPS.
ARG MJ_URL=https://ftp.mj2.org/pub/mj2/snapshots/2011-02/majordomo-20110203.tar.gz

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
# Majordomo 2 (2011) uses relative `require "setup/..."`; modern perl dropped
# '.' from @INC, so re-enable the legacy behaviour build-wide and at runtime.
ENV PERL_USE_UNSAFE_INC=1

# System perl + apache + every Perl module Makefile.PL checks for. Digest::SHA1
# was dropped from bullseye and is supplied by a shim below.
# The benchmark Debian mirror (deb.debian.org -> 198.18.1.105) is flaky from
# build containers; Acquire::Retries absorbs the transient timeouts.
RUN apt-get -o Acquire::Retries=8 -o Acquire::http::Timeout=30 update \
 && apt-get -o Acquire::Retries=8 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
      perl make apache2 ca-certificates curl \
      libmime-tools-perl libnet-perl libio-stringy-perl libdate-manip-perl \
      libcgi-pm-perl libhtml-format-perl libhtml-tree-perl libtext-reflow-perl \
 && rm -rf /var/lib/apt/lists/*

# Digest::SHA1 compatibility shim (env dependency, not app code).
COPY conf/Digest_SHA1.pm /usr/local/share/perl/5.32.1/Digest/SHA1.pm

# Unprivileged account Majordomo runs as (matches uid/gid in .mj_config).
RUN groupadd -f majordom \
 && useradd -r -g majordom -d /usr/local/majordomo -s /usr/sbin/nologin majordom

# Fetch + unpack the pinned snapshot into a majordom-owned build tree.
# NOTE: the benchmark archive mirror (ftp.mj2.org) only completes TLS <= 1.2
# handshakes from build containers (1.3 gets SSL_ERROR_SYSCALL); --tls-max 1.2
# restores the plain curl fetch without touching the pinned URL.
RUN mkdir -p /opt/mjbuild \
 && curl -fsSL --tls-max 1.2 "$MJ_URL" -o /tmp/mj.tar.gz \
 && tar xzf /tmp/mj.tar.gz -C /opt/mjbuild --strip-components=1 \
 && rm -f /tmp/mj.tar.gz

# Pre-seeded installer config (skips all interactive prompts) + no-op mta stub.
COPY conf/mj_config /opt/mjbuild/.mj_config
COPY conf/mta_none.pl /opt/mjbuild/setup/mta_none.pl

# Target dirs, owned by majordom so the whole install runs unprivileged
# (Majordomo's own scripts refuse to run as root).
RUN mkdir -p /usr/local/majordomo/cgi-bin /etc/majordomo \
 && chown -R majordom:majordom /opt/mjbuild /usr/local/majordomo /etc/majordomo

# Build + install as majordom. `yes ""` accepts the (few, all-defaulted)
# pre-config prompts; the pre-seeded .mj_config suppresses the rest.
RUN cd /opt/mjbuild \
 && runuser -u majordom -- bash -c 'yes "" | perl Makefile.PL' \
 && runuser -u majordom -- make \
 && runuser -u majordom -- make install \
 && test -x /usr/local/majordomo/cgi-bin/mj_wwwusr \
 && test -d /usr/local/majordomo/lists/lists.pcb.test/GLOBAL

# Apache: run as majordom (so the CGI uid/gid self-check passes), serve the
# installed cgi-bin, quiet the ServerName warning.
COPY conf/majordomo-apache.conf /etc/apache2/conf-available/majordomo.conf
RUN a2enmod cgid >/dev/null \
 && a2enconf majordomo >/dev/null \
 && a2disconf serve-cgi-bin >/dev/null 2>&1 || true; \
    sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=majordom/; \
            s/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=majordom/' /etc/apache2/envvars \
 && echo "ServerName localhost" >> /etc/apache2/apache2.conf

EXPOSE 80
