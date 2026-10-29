# PatchClosure-Bench recipe for goshs-cve-2026-54719.
# Uses official goshs release binaries (pinned per profile). Stable versions use
# the .deb asset; v2.0.0-beta.3 (pre-fix) uses the tar.gz asset.
# .goshs per-folder ACL protects /protected/; canary planted by entrypoint.
FROM debian:bookworm-slim

ARG GOSHS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates binutils tar && rm -rf /var/lib/apt/lists/*

RUN if [ "${GOSHS_VERSION}" = "2.0.0-beta.3" ]; then \
      curl -sL -o /tmp/g.tgz "https://github.com/goshs-labs/goshs/releases/download/v${GOSHS_VERSION}/goshs_linux_x86_64.tar.gz" \
      && tar -xzf /tmp/g.tgz -C /tmp && mv /tmp/goshs /usr/local/bin/goshs; \
    else \
      curl -sL -o /tmp/g.deb "https://github.com/goshs-labs/goshs/releases/download/v${GOSHS_VERSION}/goshs_${GOSHS_VERSION}_linux_amd64.deb" \
      && cd /tmp && ar x g.deb && tar -xf data.tar.* && mv /tmp/usr/bin/goshs /usr/local/bin/goshs; \
    fi \
 && chmod +x /usr/local/bin/goshs && rm -rf /tmp/*

COPY goshs.conf.json /goshs-acl-template.json

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/goshs"]
