# REAL software: build the REAL OpenSSL release from source per version and install the
# REAL tools/c_rehash (generated from tools/c_rehash.in during the build) plus the REAL
# openssl binary it shells out to. NO script lifting, NO stub openssl.
#
#   OSSL_VER = 1.1.1n (V0, pre CVE-2022-1292)
#            = 1.1.1o (V1, CVE-2022-1292 fix -> incomplete TARGET)
#            = 1.1.1p (V2, CVE-2022-2068 fix)
FROM debian:bookworm-slim

ARG OSSL_VER
ENV OSSL_VER=${OSSL_VER}
ENV PREFIX=/opt/ossl
ENV PATH=/opt/ossl/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Download the REAL upstream release tarball and compile it.  build_programs + tools/c_rehash
# builds the libraries + apps/openssl + the real generated c_rehash WITHOUT the test tree.
RUN set -eux; \
    TAG="OpenSSL_$(echo "${OSSL_VER}" | tr . _)"; \
    curl -fsSL -o openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/${TAG}/openssl-${OSSL_VER}.tar.gz"; \
    tar xzf openssl.tar.gz; \
    cd "openssl-${OSSL_VER}"; \
    ./config --prefix=${PREFIX} --openssldir=${PREFIX}/ssl no-shared; \
    make -j"$(nproc)" build_programs tools/c_rehash; \
    make install_sw; \
    if [ ! -x ${PREFIX}/bin/c_rehash ]; then \
        make tools/c_rehash; cp tools/c_rehash ${PREFIX}/bin/c_rehash; \
    fi; \
    chmod +x ${PREFIX}/bin/c_rehash; \
    ${PREFIX}/bin/openssl version; \
    head -1 ${PREFIX}/bin/c_rehash; \
    cd /; rm -rf /build

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
