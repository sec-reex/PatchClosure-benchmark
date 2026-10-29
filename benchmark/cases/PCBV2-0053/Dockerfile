# Faithful sink image for the OWASP AntiSamy PRESERVE-COMMENTS mXSS incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned AntiSamy version (build-arg ANTISAMY_VER):
#   v0 = 1.7.3 (pre-CVE-2023-43643: preserved-comment mXSS executes)
#   v1 = 1.7.4 (CVE-2023-43643 fix = TARGET, incomplete: original blocked, bang-comment residual survives)
#   v2 = 1.7.5 (CVE-2024-23635 fix = COMPLETE: neko-htmlunit bump + serializer fix close the residual)
# Maven resolves AntiSamy + its transitive parser dep neko-htmlunit from Central at build. Unlike a
# pure-code fix, the comment-parsing fix lives largely in the neko-htmlunit dependency, so the
# transitive neko version is DELIBERATELY LEFT to track each AntiSamy release (1.7.3->neko 3.1.0,
# 1.7.4->3.6.0, 1.7.5->3.11.1) -- that dependency+code evolution IS the guard being differentiated.
ARG ANTISAMY_VER=1.7.4

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
