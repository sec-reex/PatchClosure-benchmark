# PatchClosure-Bench env for spring-framework-cve-2024-22259
# (CVE-2024-22243 -> CVE-2024-22259, Spring Framework UriComponentsBuilder
#  host-parsing open-redirect / SSRF).
#
# Recipe-based: NO vendored jars/images. At build time we pull the PUBLISHED
# org.springframework:spring-web:${SPRING_VERSION} + transitive deps from Maven
# Central, then compile the tiny Driver.java that invokes the REAL, unmodified
# UriComponentsBuilder.fromUriString(...).build().getHost() guard. Node.js is the
# browser-equivalent navigation resolver (WHATWG URL) that performs the real
# downstream fetch; python3 drives the data-side harness. No Spring code is edited.
ARG SPRING_VERSION=6.1.4
FROM maven:3.9-eclipse-temurin-17
ARG SPRING_VERSION
WORKDIR /work
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && ( command -v node >/dev/null || ln -sf "$(command -v nodejs)" /usr/local/bin/node )
COPY pom.xml /work/pom.xml
# Pull spring-web + all transitive deps for the pinned version into /work/libs.
RUN mvn -q -Dspring.version=${SPRING_VERSION} \
        dependency:copy-dependencies -DoutputDirectory=/work/libs
COPY Driver.java /work/Driver.java
COPY nav.js /work/nav.js
COPY gateway.py /work/gateway.py
RUN javac -cp "/work/libs/*" -d /work/classes /work/Driver.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
CMD ["python3", "/work/gateway.py"]
