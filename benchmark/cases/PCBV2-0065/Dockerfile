# REAL image: builds an axum service that depends on the REAL published `activitypub-federation`
# crate (from crates.io) at the version given by ARG AP_VER, plus a std-only loopback flag sidecar.
# The crate's OWN SSRF guard (verify_url_valid) runs inside its real fetch_object_http path -- no
# guard code is lifted. rustls (aws-lc-rs/ring) needs a C toolchain + cmake + perl to build.
FROM rust:slim
ARG AP_VER
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config perl cmake ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY service/ /app/service/
# Pin the REAL crate version for this profile (v0/v1/v2) and build the real service + sidecar.
RUN cd /app/service \
    && sed -i "s|__AP_VER__|${AP_VER}|" Cargo.toml \
    && cargo build \
    && cp target/debug/service /usr/local/bin/service \
    && cp target/debug/sidecar /usr/local/bin/sidecar \
    && rm -rf target ~/.cargo/registry ~/.cargo/git

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
