# Faithful-core: official Maven+Temurin base building a tiny, UNMODIFIED Netty
# HTTP server against a pinned io.netty:netty-codec-http release. The version's
# own HttpObjectDecoder is the request-framing guard under test.
FROM maven:3.9-eclipse-temurin-8
ARG NETTY_VER=4.1.43.Final
ENV NETTY_VER=${NETTY_VER}
WORKDIR /app
# Resolve netty-codec-http (+ transitive netty jars) for the exact pinned version.
COPY pom.xml /app/pom.xml
RUN mvn -q -Dnetty.version=${NETTY_VER} dependency:copy-dependencies -DoutputDirectory=/app/libs
# Compile the harness against those jars.
COPY src /app/src
RUN mvn -q -Dnetty.version=${NETTY_VER} compile
EXPOSE 8080
CMD ["sh", "-c", "java -Dnettyver=${NETTY_VER} -cp /app/target/classes:/app/libs/* Server"]
