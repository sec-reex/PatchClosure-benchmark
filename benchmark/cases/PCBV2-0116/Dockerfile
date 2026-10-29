# PatchClosure-Bench — git-submodule-url-dash-argument-injection
# Builds one Git version from source (build-arg GIT_VER), for the 3-version
# differential V0=2.13.4 / V1=2.14.1 / V2=2.19.1.
#
# openssh-client is installed so the CVE-2017-1000117 (ssh-host-dash) vector's
# ProxyCommand path is exercisable. Everything is local (file://) — no network
# clone happens at probe time.
FROM debian:bullseye-slim
# PatchClosure: Debian bullseye is EOL; its deb/security pool point-releases were purged from the
# mirrors (build-time apt 404). Redirect to archive.debian.org. Guarded on bullseye so non-bullseye
# bases are untouched.
RUN if grep -qs bullseye /etc/apt/sources.list; then sed -i -E 's@https?://(deb|security)\.debian\.org@http://archive.debian.org@g' /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99archive; fi

ARG GIT_VER

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates wget \
        zlib1g-dev libssl-dev libcurl4-openssl-dev libexpat1-dev \
        openssh-client perl; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    cd /tmp; \
    wget -q -O git.tar.xz \
        "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${GIT_VER}.tar.xz"; \
    tar xf git.tar.xz; \
    cd "git-${GIT_VER}"; \
    make -j"$(nproc)" prefix=/usr/local NO_GETTEXT=1 NO_TCLTK=1 NO_PYTHON=1 all; \
    make prefix=/usr/local NO_GETTEXT=1 NO_TCLTK=1 NO_PYTHON=1 install; \
    cd /; rm -rf /tmp/git-*; \
    git --version

# Neutral identity so `git commit` works when constructing the malicious repo.
ENV GIT_AUTHOR_NAME=pcb GIT_AUTHOR_EMAIL=pcb@example.invalid \
    GIT_COMMITTER_NAME=pcb GIT_COMMITTER_EMAIL=pcb@example.invalid \
    EMAIL=pcb@example.invalid

WORKDIR /work
