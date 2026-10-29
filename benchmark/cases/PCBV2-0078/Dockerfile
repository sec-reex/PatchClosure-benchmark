# PatchClosure-Bench env for apache-shiro-cve-2020-13933.
# Multi-stage: build the minimal Spring Boot app against the REAL published Apache
# Shiro artifacts at a pinned version (build-arg SHIRO_VER = 1.5.2 / 1.5.3 / 1.6.0),
# then run the fat jar on a JRE. No Shiro source is edited.
ARG SHIRO_VER=1.5.3
FROM maven:3.8-eclipse-temurin-8 AS build
ARG SHIRO_VER
WORKDIR /src
COPY pom.xml /src/pom.xml
# Warm the dependency cache for this shiro version (best-effort; ignore failures).
RUN mvn -q -Dshiro.version=${SHIRO_VER} -DskipTests dependency:go-offline || true
COPY src /src/src
RUN mvn -q -Dshiro.version=${SHIRO_VER} -DskipTests package

FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /src/target/app.jar /app/app.jar
EXPOSE 8080
# ${PCB_FLAG} arrives via the environment at container runtime (compose).
CMD ["java", "-jar", "/app/app.jar"]
