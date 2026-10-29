# V0 only: official images start at 2.0.1, which already has the CVE-2026-27598
# CREATE guard. This commit is the parent of e2ed589 / PR #1691.
ARG DAGU_REF=6c53bfdaa6beec62a3936b8c5b233efb8bd22c7b
FROM golang:1.26-alpine AS build
ARG DAGU_REF
RUN apk add --no-cache ca-certificates curl
WORKDIR /src
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOTOOLCHAIN=local
# Archive tarball is reliable for a raw commit SHA (shallow git fetch often misses it).
# Org moved dagu-org -> dagucloud; try both.
RUN set -eux; \
    curl -fsSL "https://github.com/dagu-org/dagu/archive/${DAGU_REF}.tar.gz" -o /tmp/src.tgz \
    || curl -fsSL "https://github.com/dagucloud/dagu/archive/${DAGU_REF}.tar.gz" -o /tmp/src.tgz; \
    tar -xzf /tmp/src.tgz -C /src --strip-components=1; \
    rm -f /tmp/src.tgz
RUN mkdir -p /out && CGO_ENABLED=0 go build -o /out/dagu ./cmd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/dagu /usr/local/bin/dagu
ENTRYPOINT ["/bin/sh","-c","\
  set -e; \
  mkdir -p /data/dags /flag; \
  printf '# dagu canary (outside DAGs dir)\\nname: %s\\n' \"${PCB_FLAG:?set PCB_FLAG}\" > /flag/canary.yaml; \
  printf 'name: hello\\nsteps:\\n  - command: echo hi\\n' > /data/dags/hello.yaml; \
  exec dagu server \
"]
