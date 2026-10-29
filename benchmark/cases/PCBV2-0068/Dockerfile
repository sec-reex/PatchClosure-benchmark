# PatchClosure-Bench env for apache-dolphinscheduler-cve-2024-23320
# (CVE-2023-49299 -> CVE-2024-23320, Apache DolphinScheduler switch-task
#  unsandboxed JavaScript expression evaluation -> code injection, CWE-94 / CWE-20).
#
# REAL Java HTTP service triggered by an EXTERNAL HTTP request. Faithful-core,
# recipe-based: NO vendored jars. At build time we pull the PUBLISHED
# org.apache.dolphinscheduler:dolphinscheduler-master:${DS_VERSION} (which contains the
# REAL, unmodified org.apache.dolphinscheduler.server.master.utils.SwitchTaskUtils
# JS-eval sink + guard) and dolphinscheduler-task-api (Property model) from Maven
# Central, plus the handful of runtime libs the two exercised methods reference
# (commons-collections4 MapUtils, commons-lang3 NumberUtils, guava Maps, slf4j-api,
# jackson for the HTTP JSON I/O). Server.java is a tiny com.sun.net.httpserver service
# that reflectively invokes the REAL SwitchTaskUtils methods on the POSTed switch
# condition. No DS code is modified. eclipse-temurin:11-jdk is used because the switch
# task evaluates the condition through the JDK-builtin Nashorn "js" ScriptEngine (removed
# from JDK 15+); DolphinScheduler 3.1/3.2 target Java 8/11, so 11 is the faithful runtime.
# --- stage 1: fetch the published jars (curlimages/curl already has curl; no apt needed,
#     which avoids the flaky ports.ubuntu.com ARM mirror during build). ---
FROM curlimages/curl:8.8.0 AS fetch
ARG DS_VERSION=3.1.9
WORKDIR /libs
RUN set -eu; base=https://repo1.maven.org/maven2; \
    curl -fsSL -o "dolphinscheduler-master-${DS_VERSION}.jar" \
      "$base/org/apache/dolphinscheduler/dolphinscheduler-master/${DS_VERSION}/dolphinscheduler-master-${DS_VERSION}.jar"; \
    curl -fsSL -o "dolphinscheduler-task-api-${DS_VERSION}.jar" \
      "$base/org/apache/dolphinscheduler/dolphinscheduler-task-api/${DS_VERSION}/dolphinscheduler-task-api-${DS_VERSION}.jar"; \
    curl -fsSL -o commons-collections4.jar       "$base/org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar"; \
    curl -fsSL -o commons-lang3.jar              "$base/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"; \
    curl -fsSL -o guava.jar                      "$base/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar"; \
    curl -fsSL -o failureaccess.jar              "$base/com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.jar"; \
    curl -fsSL -o slf4j-api.jar                  "$base/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar"; \
    curl -fsSL -o jackson-annotations.jar        "$base/com/fasterxml/jackson/core/jackson-annotations/2.13.3/jackson-annotations-2.13.3.jar"; \
    curl -fsSL -o jackson-core.jar               "$base/com/fasterxml/jackson/core/jackson-core/2.13.3/jackson-core-2.13.3.jar"; \
    curl -fsSL -o jackson-databind.jar           "$base/com/fasterxml/jackson/core/jackson-databind/2.13.3/jackson-databind-2.13.3.jar"

# --- stage 2: the REAL Java HTTP service runtime. ---
FROM eclipse-temurin:11-jdk
ARG DS_VERSION=3.1.9
WORKDIR /work
COPY --from=fetch /libs /work/libs
# Server uses com.sun.net.httpserver (JDK builtin) + jackson (JSON) + reflection into the
# DS jars, so it compiles against jackson only (no compile-time DS dependency).
COPY Server.java /work/Server.java
RUN javac -cp "/work/libs/*" -d /work/classes /work/Server.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
EXPOSE 8080
# canary planted at run-time from ${PCB_FLAG} into a file OUTSIDE any app dir, then the
# REAL HTTP service starts in the foreground.
CMD ["sh","-c","mkdir -p /canary && printf '%s' \"$PCB_FLAG\" > /canary/flag.txt && chmod 0644 /canary/flag.txt && exec java -cp \"$(cat /work/cp.txt)\" Server"]
