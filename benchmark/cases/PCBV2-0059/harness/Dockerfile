# ROUND9 rebuilt harness for hapi-fhir-org-hl7-fhir-core-cve-2026-55470.
# Reconstructed from repro.log + case.json (construction gate record); the original
# harness/ directory was lost. Runs the REAL published org.hl7.fhir.dstu2 engine
# behind a com.sun.net.httpserver.HttpServer (POST /eval + GET /health).
FROM maven:3.9-eclipse-temurin-17

ARG FHIR_VER
ENV FHIR_VER=${FHIR_VER}
ENV PORT=8080

WORKDIR /app
COPY pom.xml ./pom.xml
COPY src ./src

# Whole published ca.uhn.hapi.fhir:org.hl7.fhir.dstu2 from Maven Central (not a sliced source file).
RUN mvn -q -B dependency:resolve compile \
 && mvn -q -B dependency:tree -Dincludes=ca.uhn.hapi.fhir:org.hl7.fhir.dstu2 > /app/dep-tree.txt \
 && grep -E 'org\.hl7\.fhir\.dstu2' /app/cp.txt /app/dep-tree.txt

EXPOSE 8080
CMD ["sh", "-c", "exec java -cp target/classes:$(cat /app/cp.txt) Server"]
