# PatchClosure-Bench env for spring-framework-cve-2022-22965 (Spring4Shell).
#
# Multi-stage: Maven builds the minimal Spring MVC WAR, then it is deployed
# as a traditional WAR on Tomcat (JDK 9+ required so java.lang.Class.getModule()
# exists -- the CVE-2022-22965 bypass path via class.module.classLoader).
#
# Build-arg SPRING_VER selects the Spring Framework version:
#   5.3.17 = V1 (CVE-2010-1622 blocklist, pre-Spring4Shell = TARGET)
#   5.3.18 = V2 (CVE-2022-22965 fix applied)
#
# Build-arg MAVEN_IMAGE / TOMCAT_IMAGE allow switching JDK for V0 (JDK8).
ARG MAVEN_IMAGE=maven:3.8-eclipse-temurin-17
ARG TOMCAT_IMAGE=tomcat:9.0.60-jdk17-temurin
ARG SPRING_VER=5.3.17

# --- build stage ---
FROM ${MAVEN_IMAGE} AS build
ARG SPRING_VER
WORKDIR /build
COPY app/pom.xml pom.xml
COPY app/src src
# Override Spring version at build time via Maven property.
RUN mvn -q package -DskipTests -Dspring.version=${SPRING_VER} \
    && ls -la target/app.war

# --- runtime stage ---
FROM ${TOMCAT_IMAGE}
# Remove default webapps so only our app is deployed.
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=build /build/target/app.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080
CMD ["catalina.sh", "run"]
