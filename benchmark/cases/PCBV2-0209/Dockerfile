# PatchClosure-Bench env for undertow-jboss-wildfly-web-server-cve-2018-1067
# (CVE-2016-4993 -> CVE-2018-1067, Undertow HTTP response splitting / CRLF header injection,
#  CWE-113). Genuine incomplete-fix pair.
#
# Faithful-core, recipe-based: NO vendored jars. At build time Maven pulls the EXACT published
# io.undertow:undertow-core:${UNDERTOW_VERSION} (+ transitive xnio / jboss-logging) from Maven
# Central -- the REAL, unmodified HttpResponseConduit.writeString code whose CR/LF guard is what
# CVE-2016-4993 added and CVE-2018-1067 re-hardened. ReflectServer.java runs the REAL Undertow
# server, bound to 0.0.0.0:8080 and PUBLISHED to a host port (see docker-compose.yml). The trigger
# is a fully EXTERNAL raw-HTTP socket from the host. No Undertow code modified.
FROM maven:3.9-eclipse-temurin-8
ARG UNDERTOW_VERSION=1.4.3.Final
WORKDIR /work
COPY pom.xml /work/pom.xml
# Resolve + copy undertow-core@${UNDERTOW_VERSION} and its transitive deps into /work/libs.
RUN mvn -B -q -Dundertow.version=${UNDERTOW_VERSION} \
        dependency:copy-dependencies -DoutputDirectory=/work/libs
COPY ReflectServer.java /work/ReflectServer.java
RUN mkdir -p /work/classes \
 && javac -cp "/work/libs/*" -d /work/classes /work/ReflectServer.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
EXPOSE 8080
# Main process = the REAL Undertow server, bound to 0.0.0.0:8080 inside the container and published
# to a host port by compose. External clients trigger it over a raw HTTP socket to the host port.
CMD ["sh","-c","java -cp \"$(cat /work/cp.txt)\" ReflectServer"]
