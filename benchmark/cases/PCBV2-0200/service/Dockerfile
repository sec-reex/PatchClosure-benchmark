# Build a REAL Jinjava HTTP render service pinned to a specific published jinjava
# version. JINJAVA_VER selects the profile: 2.8.0 (V0), 2.8.1 (V1/target), 2.8.3 (V2).
# jinjava 2.8.x jars are Java-17 class files => eclipse-temurin-17.
ARG JINJAVA_VER=2.8.1

FROM maven:3.9-eclipse-temurin-17 AS build
ARG JINJAVA_VER
WORKDIR /src
COPY pom.xml .
COPY src ./src
# Pull com.hubspot.jinjava:jinjava:${JINJAVA_VER} + deps from Maven Central; fat jar.
RUN mvn -q -Djinjava.version=${JINJAVA_VER} -DskipTests package

FROM eclipse-temurin:17-jre
COPY --from=build /src/target/app.jar /app/app.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
