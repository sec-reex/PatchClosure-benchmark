# REAL File Browser boot image for the CVE-2026-32760 -> CVE-2026-34528 incomplete-fix pair.
# Boots the ACTUAL published File Browser binary from the official image (filebrowser/filebrowser:v<ver>);
# it does NOT lift/vendor any upstream Go source. The privilege-escalation bypass is triggered by an
# EXTERNAL HTTP request (self-register via POST /api/signup, then use the new user's token).
#
#   FB_VERSION=v2.61.2  -> V0 (pre-CVE-2026-32760: signup strips nothing; user inherits Admin+Execute)
#   FB_VERSION=v2.62.0  -> V1 (CVE-2026-32760 fix a63573b: strips Admin only; Execute LEAKS = residual) <- target
#   FB_VERSION=v2.62.2  -> V2 (CVE-2026-34528 fix: also strips Execute + empties Commands; closed)
ARG FB_VERSION=v2.62.0
FROM filebrowser/filebrowser:${FB_VERSION}

USER root
# flag dir OUTSIDE the served root /srv (so the file API cannot reach the exec-channel canary),
# writable by the unprivileged runtime user the official image runs as.
RUN mkdir -p /opt/flagdir && chown user:user /opt/flagdir && chmod 755 /opt/flagdir
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER user
EXPOSE 80
# tini for signal handling + zombie reaping (the command runner spawns child processes).
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
