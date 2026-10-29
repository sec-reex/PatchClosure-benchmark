# PatchClosure-Bench REAL web-app env for resteasy-jboss-cve-2014-3490
# (CVE-2012-0818 [XXE via external GENERAL entity] -> CVE-2014-3490 [XXE via external PARAMETER entity;
#  INCOMPLETE fix], RESTEasy JAXB provider XXE, CWE-611).
#
# A REAL RESTEasy JAX-RS web application, triggered by an EXTERNAL HTTP request:
#   POST /app/xml  (Content-Type: application/xml)  -> JAXB-unmarshalled by the REAL, unmodified
#   published RESTEasy JAXB provider into a @XmlRootElement Foo bean; the resource returns the bean's
#   value, so an XXE-resolved file read surfaces in the HTTP response.
#
# Stage 1 (maven:3.9-eclipse-temurin-8): Maven pulls the EXACT published
#   org.jboss.resteasy:resteasy-jaxrs + resteasy-jaxb-provider at ${RESTEASY_VERSION} (+ transitive
#   deps, incl. the version-correct JAX-RS API) from Maven Central and builds app.war. No app code
#   touches RESTEasy internals; only standard JAX-RS annotations are used.
# Stage 2 (tomcat:8.5-jre8): deploy app.war as context /app on real Apache Tomcat. The BENIGN
#   read-exfil canary ${PCB_FLAG} is planted at /flag by the compose command at container start.
ARG RESTEASY_VERSION=3.0.8.Final

FROM maven:3.9-eclipse-temurin-8 AS build
ARG RESTEASY_VERSION
WORKDIR /src
COPY pom.xml /src/pom.xml
COPY src /src/src
# Pull the EXACT resteasy-jaxrs + resteasy-jaxb-provider ${RESTEASY_VERSION} + transitive deps; build app.war.
RUN mvn -q -B -Dresteasy.version=${RESTEASY_VERSION} -DskipTests package \
 && test -f /src/target/app.war

FROM tomcat:8.5-jre8
# Deploy under context /app (does not collide with Tomcat's default ROOT webapp -> no rm needed).
COPY --from=build /src/target/app.war /usr/local/tomcat/webapps/app.war
EXPOSE 8080
