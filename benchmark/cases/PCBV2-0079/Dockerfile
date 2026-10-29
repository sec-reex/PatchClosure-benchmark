# PatchClosure-Bench env for apache-struts-cve-2021-31805
# (CVE-2020-17530 [S2-061] -> CVE-2021-31805 [S2-062], Apache Struts 2 forced double OGNL
#  evaluation of UI-tag attributes, CWE-917 EL-injection). Genuine incomplete fix.
#
# REAL Struts 2 WAR on Tomcat, triggered by an EXTERNAL HTTP request (no in-process driver).
# Recipe-based, NO vendored jars: Maven pulls the EXACT published struts2-core:${STRUTS_VER} + its
# real, unmodified transitive deps (OGNL, freemarker, xwork, and on 2.5.30 the S2-062
# NotExcludedAcceptedPatternsChecker) from Central and assembles a minimal WAR. A REAL <s:textfield>
# UI tag forced-OGNL-evaluates a request-supplied action property in its id/name attribute; the
# version's own unmodified UIBean/Component code alone decides whether it double-evaluates.
# Runtime = Tomcat 9 (javax.servlet + Jasper/JSP) on JDK 8 (Struts 2.5.x targets Java 8).
# BENIGN CANARY: the attacker OGNL only reads the planted context var #pcbflag (= ${PCB_FLAG});
# no webshell / exec / reflection / static-method call.
FROM maven:3.9-eclipse-temurin-8 AS build
ARG STRUTS_VER=2.5.26
WORKDIR /build
COPY webapp/ /build/
RUN mkdir -p /build/src/main/java/pcb /build/src/main/resources \
 && cp /build/actions/EvalAction.java /build/src/main/java/pcb/EvalAction.java \
 && cp /build/struts.xml /build/src/main/resources/struts.xml
RUN mvn -B -Dstruts.version=${STRUTS_VER} package || mvn -B -Dstruts.version=${STRUTS_VER} package

FROM tomcat:9.0-jdk8-corretto
ENV PCB_FLAG=changeme
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /build/target/ROOT.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
