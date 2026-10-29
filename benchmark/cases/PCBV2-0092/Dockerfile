# Real-library-wrap image for the cyclonedx-core-java XXE incomplete-fix pair.
# Maven pulls the REAL org.cyclonedx:cyclonedx-core-java:${CDX_VER} (published bytes) from Central.
# The ONLY thing that varies across v0/v1/v2 is CDX_VER:
#   v0 = 8.0.0   v1 = 9.0.4 (TARGET)   v2 = 11.0.1
ARG CDX_VER=9.0.4

FROM maven:3.9-eclipse-temurin-17 AS build
ARG CDX_VER
WORKDIR /build
COPY pom.xml /build/pom.xml
COPY App.java /build/src/main/java/App.java
RUN mvn -q -B -Dcdx.version=${CDX_VER} clean package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /build/target/cdx-xxe-sink.jar /app/cdx-xxe-sink.jar
EXPOSE 80
# Plant the per-run flag at /flag (outside the app, no trailing newline) then run the real-library sink.
CMD ["sh", "-c", "printf '%s' \"$PCB_FLAG\" > /flag && exec java -jar /app/cdx-xxe-sink.jar"]
