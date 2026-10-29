# Apache HTTP Server 2.2.21 built from source (archive.apache.org), pinned.
# Recipe-only: no vendored source; the tarball is fetched at build time.
# One base configure (cached); PATCHLEVEL selects the server/protocol.c patch
# level (v0 pristine / v1 = +r1179239 / v2 = +r1188745) so the three images
# differ ONLY in the mod_proxy request-URI guard. See patch_protocol.py.
FROM debian:bullseye-slim
# PatchClosure: Debian bullseye is EOL and its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org so apt installs resolve. Guarded on
# bullseye so any non-bullseye base is left untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl python3 autotools-dev \
      libapr1-dev libaprutil1-dev libpcre3-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src
RUN curl -fsSL -o httpd-2.2.21.tar.bz2 \
      https://archive.apache.org/dist/httpd/httpd-2.2.21.tar.bz2 \
 && tar xjf httpd-2.2.21.tar.bz2 \
 && rm httpd-2.2.21.tar.bz2

# Configure once (independent of protocol.c content -> shared cache layer).
# The 2008-era bundled config.guess/config.sub don't recognize aarch64, so refresh
# them and pass an explicit build triplet.
WORKDIR /usr/local/src/httpd-2.2.21
RUN cp /usr/share/misc/config.guess /usr/share/misc/config.sub build/ \
 && BUILD_TRIPLET="$(/usr/share/misc/config.guess)" \
 && ./configure --prefix=/usr/local/apache2 \
      --build="${BUILD_TRIPLET}" \
      --with-apr=/usr/bin/apr-1-config \
      --with-apr-util=/usr/bin/apu-1-config \
      --enable-proxy --enable-proxy-http --enable-rewrite \
      --disable-ssl >/tmp/configure.log 2>&1 || (tail -40 /tmp/configure.log; false)

# Apply the version-specific mod_rewrite.c / mod_proxy.c guard patch, then build.
ARG PATCHLEVEL=v0
COPY patch_source.py /usr/local/src/patch_source.py
RUN python3 /usr/local/src/patch_source.py "${PATCHLEVEL}" \
 && make -j"$(nproc)" >/tmp/make.log 2>&1 || (tail -60 /tmp/make.log; false) \
 && make install >/tmp/install.log 2>&1 || (tail -40 /tmp/install.log; false)

COPY conf/httpd.conf /usr/local/apache2/conf/httpd.conf

EXPOSE 80 8080
# -X: run in the foreground (single child) so the container's PID 1 stays alive.
CMD ["/usr/local/apache2/bin/httpd", "-X", "-f", "/usr/local/apache2/conf/httpd.conf"]
