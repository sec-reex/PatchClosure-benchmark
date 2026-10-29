# PatchClosure-Bench env for struts-fileupload-interceptor-path-traversal-rce
# (CVE-2023-50164 [S2-066] -> CVE-2024-53677 [S2-067], Apache Struts 2 file-upload path-traversal
#  via the legacy FileUploadInterceptor, CWE-434/CWE-22). Genuine incomplete fix.
#
# Recipe-based, NO vendored jars: Maven pulls the EXACT published struts2-core:${STRUTS_VER} + real
# transitive deps from Central and assembles a minimal WAR that drives struts' own unmodified
# upload path. MODE selects the action + upload mechanism faithful to that version:
#   MODE=legacy   (v0 6.3.0, v1 6.3.0.2) -> FileUploadInterceptor + File/uploadFileName action.
#   MODE=migrated (v2 6.4.0)              -> ActionFileUploadInterceptor + UploadedFilesAware action
#                                           (the S2-067 remediation).
# Runtime = Tomcat 9 (javax.servlet; struts 6.3/6.4 are still javax + commons-fileupload 1.x).
# BENIGN CANARY: uploaded body is a JSP echoing System.getenv("PCB_FLAG"); no webshell/exec.
FROM maven:3.9-eclipse-temurin-8 AS build
ARG STRUTS_VER=6.3.0.2
ARG MODE=legacy
WORKDIR /build
COPY webapp/ /build/
RUN mkdir -p /build/src/main/java/pcb /build/src/main/resources \
 && if [ "$MODE" = "migrated" ]; then \
        cp /build/actions/UploadActionMigrated.java /build/src/main/java/pcb/UploadAction.java; \
    else \
        cp /build/actions/UploadActionLegacy.java   /build/src/main/java/pcb/UploadAction.java; \
    fi \
 && cp /build/struts.xml /build/src/main/resources/struts.xml
RUN mvn -B -Dstruts.version=${STRUTS_VER} package || mvn -B -Dstruts.version=${STRUTS_VER} package

FROM tomcat:9.0.60-jdk17-temurin
ENV PCB_FLAG=changeme
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /build/target/ROOT.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
