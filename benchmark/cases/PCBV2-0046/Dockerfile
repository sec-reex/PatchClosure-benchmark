# PatchClosure-Bench recipe for awstats-cve-2020-35176.
# Recipe-based: NO committed source/images. AWStats is git-cloned at a pinned tag
# at BUILD time; only small text files live in this case dir.
#
# One parametrised Dockerfile, driven by AWSTATS_REF (compose passes it per profile):
#   v0 = 7.7  -> vulnerable to CVE-2020-29600 (Read_Config keeps the
#               File::Spec->rel2abs absolute-path fallback => an ABSOLUTE config=
#               path opens an out-of-tree file).
#   v1 = 7.8  -> CVE-2020-29600 patched (rel2abs fallback commented out) but
#               INCOMPLETELY: @PossibleConfigDir still contains "/etc", so a
#               PARTIAL absolute path (no leading /etc, no `..`) is opened as
#               "/etc/<partial>" == CVE-2020-35176 (the TARGET).
#   v2 = 7.9  -> CVE-2020-35176 patched ("/etc" removed from @PossibleConfigDir).
#
# The canary is planted at /etc/pcb_canary/flag.conf by the compose entrypoint
# (see docker-compose.yml) from ${PCB_FLAG}. It lives UNDER /etc (a config search
# dir in 7.8) but NOT under any AWStats config dir (/etc/awstats), so only the
# partial-path traversal reaches it. No application/business code is modified.
FROM debian:bookworm-slim

ARG AWSTATS_REF=7.8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 perl git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Pinned AWStats source (single self-contained Perl CGI + its lang/lib/plugins).
RUN git clone --depth 1 --branch "${AWSTATS_REF}" https://github.com/eldy/awstats.git /opt/awstats \
 && cp -a /opt/awstats/wwwroot/cgi-bin/. /usr/lib/cgi-bin/ \
 && chmod 755 /usr/lib/cgi-bin/awstats.pl \
 && rm -rf /opt/awstats

# Standard Debian CGI wiring: /usr/lib/cgi-bin served as /cgi-bin/ via mod_cgid.
RUN a2enmod cgid \
 && echo "ServerName localhost" >> /etc/apache2/apache2.conf

EXPOSE 80
