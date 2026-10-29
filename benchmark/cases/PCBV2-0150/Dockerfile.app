# REAL Netty app image for netty-cve-2026-42578 (CVE-2025-67735 -> CVE-2026-42578,
# CRLF Injection / HTTP header & request-line splitting, CWE-93/CWE-113).
#
# Recipe-only (NO vendored jars): at build time we pull the EXACT published io.netty modules at
# ${NETTY_VERSION} from Maven Central -- the REAL, unmodified DefaultHttpRequest / HttpRequestEncoder
# / HttpProxyHandler / DefaultHttpHeadersFactory / HttpServerCodec code. App.java is an ordinary
# Netty HTTP server + client (no Netty code modified). It listens on APP_PORT and, on an EXTERNAL
# HTTP request, drives the REAL Netty client to make an OUTBOUND request to a SEPARATE proxy sidecar
# container over the docker network.
FROM eclipse-temurin:17-jdk
ARG NETTY_VERSION=4.1.129.Final
ENV NETTY_VERSION=${NETTY_VERSION}
WORKDIR /work
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; base=https://repo1.maven.org/maven2/io/netty; mkdir -p /work/libs; \
    for m in netty-common netty-buffer netty-resolver netty-transport \
             netty-transport-native-unix-common netty-codec netty-handler \
             netty-codec-socks netty-codec-http netty-handler-proxy; do \
      curl -fsSL -o "/work/libs/$m.jar" \
        "$base/$m/${NETTY_VERSION}/$m-${NETTY_VERSION}.jar"; \
    done
COPY App.java /work/App.java
RUN javac -cp "/work/libs/*" -d /work/classes /work/App.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
EXPOSE 8080
CMD ["sh","-c","java -Dnettyver=${NETTY_VERSION} -cp \"$(cat /work/cp.txt)\" App"]
