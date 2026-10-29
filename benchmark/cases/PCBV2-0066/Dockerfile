# Faithful sink image for the OWASP AntiSamy STYLE-tag smuggling incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned AntiSamy version (build-arg ANTISAMY_VER):
#   v0 = 1.6.5 (pre-CVE-2022-28367)
#   v1 = 1.6.6 (CVE-2022-28367 PARTIAL fix = TARGET)
#   v2 = 1.6.7 (CVE-2022-29577 COMPLETE fix)
# Maven resolves AntiSamy + its transitive deps (neko-htmlunit, batik-css, ...) from Central at build.
ARG ANTISAMY_VER=1.6.6

FROM maven:3.9-eclipse-temurin-11 AS build
ARG ANTISAMY_VER
WORKDIR /build
COPY pom.xml /build/pom.xml
COPY App.java /build/src/main/java/App.java
RUN mvn -q -B -Dantisamy.version=${ANTISAMY_VER} clean package

FROM eclipse-temurin:11-jre
WORKDIR /app
COPY --from=build /build/target/antisamy-sink.jar /app/antisamy-sink.jar
COPY antisamy.xml /app/antisamy.xml
EXPOSE 80
CMD ["java", "-jar", "/app/antisamy-sink.jar"]
