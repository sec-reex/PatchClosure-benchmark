# Faithful-core image for the Deno node:child_process shell:true OS-command-injection sink
# (pre-CVE-2026-27190 2.6.7  ->  CVE-2026-27190 fix carried in 2.7.1 [backtick single-quoted, TARGET]
#  ->  CVE-2026-32260 fix 2.7.2 [$VAR+backtick single-quoted]).
# One image: all three OFFICIAL Deno release binaries are installed side-by-side under /opt/deno/{v0,v1,v2}
# and the entrypoint runs the harness with the one selected by HARNESS_VER, so Deno.execPath() (and hence
# the version-specific transformDenoShellCommand) is exactly the published bytes of deno 2.6.7 / 2.7.1 / 2.7.2.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Official Deno install script, pinned per version (fetches the real released linux binary).
RUN set -eux; \
    for pair in v0:v2.6.7 v1:v2.7.1 v2:v2.7.2; do \
      slot="${pair%%:*}"; ver="${pair##*:}"; \
      curl -fsSL https://deno.land/install.sh | DENO_INSTALL="/opt/deno/$slot" sh -s "$ver"; \
      "/opt/deno/$slot/bin/deno" --version; \
    done

WORKDIR /app
COPY harness.ts /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
