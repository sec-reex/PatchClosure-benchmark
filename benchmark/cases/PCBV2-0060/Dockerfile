# PatchClosure-Bench env for hl7-fhir-org-hl7-fhir-core-cve-2023-28465.
# REAL HTTP upload service: pull the PUBLISHED HL7 FHIR artifact
# (ca.uhn.hapi.fhir:org.hl7.fhir.r4b:${FHIR_VERSION}) + its transitive deps from
# Maven Central, compile Server.java (a com.sun.net.httpserver.HttpServer), and
# run it. Server.java accepts an EXTERNAL HTTP zip upload on POST /unzip and
# extracts it via the REAL, unmodified TerminologyCacheManager.unzip(...) sink.
# No org.hl7.fhir code is edited; no vendored jars are committed.
ARG FHIR_VERSION=5.6.92
FROM maven:3.9-eclipse-temurin-17
ARG FHIR_VERSION
WORKDIR /work
COPY pom.xml /work/pom.xml
# Pull r4b + all transitive deps for the pinned version into /work/libs.
RUN mvn -q -Dfhir.version=${FHIR_VERSION} \
        dependency:copy-dependencies -DoutputDirectory=/work/libs
COPY Server.java /work/Server.java
RUN javac -cp "/work/libs/*" -d /work/classes /work/Server.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
EXPOSE 8080
CMD ["sh", "-c", "exec java -cp \"$(cat /work/cp.txt)\" Server"]
