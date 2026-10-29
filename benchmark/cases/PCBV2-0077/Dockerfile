# PatchClosure-Bench env for apache-log4j-2-cve-2021-45046
# (CVE-2021-44228 [Log4Shell] -> CVE-2021-45046, Apache Log4j 2 Expression-Language /
#  JNDI Lookup Injection, CWE-917). Canonical genuine incomplete-fix.
#
# Faithful-core, recipe-based: NO vendored jars. At build time we pull the EXACT published
# org.apache.logging.log4j:log4j-core + log4j-api at ${L4J_VERSION} from Maven Central
# (the REAL, unmodified JndiLookup / JndiManager / Interpolator / StrSubstitutor code). A
# tiny Driver.java uses the REAL log4j Logger API to log an attacker-controlled string and
# to set ThreadContext (MDC), with a shared, unmodified log4j2.xml whose PatternLayout uses
# a Context Lookup ($${ctx:pcbctx}) -- exactly the non-default layout CVE-2021-45046 calls out.
# No log4j code is modified.
#
# Runtime = eclipse-temurin:11-jdk (log4j 2.14-2.16 target Java 8/11; JNDI/LDAP client is the
# JDK-builtin com.sun.jndi.ldap provider). python3 runs the BENIGN internal LDAP OOB canary.
#
# BENIGN CANARY (no gadget / no class-load / no deserialization): ldap_canary.py listens ONLY
# on 127.0.0.1:1389 inside the container. When log4j's JndiLookup fires it opens an LDAP
# connection to 127.0.0.1 (an address in log4j 2.15.0's DEFAULT allowed-hosts list, so the
# 2.15.0 guard lets it through -- faithfully modelling "45046 still resolves an allowed JNDI").
# The canary completes a minimal LDAP bind, reads the search DN (which carries the per-probe
# token), records "<token>\t${PCB_FLAG}" to /canary/hits.log, and returns an EMPTY result.
# It never returns a Java object / Reference / serialized data -- the mere inbound connection
# is the signal. The flag is a planted random token, absent from log4j source and Driver.java.
FROM eclipse-temurin:11-jdk
ARG L4J_VERSION=2.15.0
WORKDIR /work
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl python3 \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; base=https://repo1.maven.org/maven2/org/apache/logging/log4j; mkdir -p /work/libs; \
    curl -fsSL -o /work/libs/log4j-core.jar "$base/log4j-core/${L4J_VERSION}/log4j-core-${L4J_VERSION}.jar"; \
    curl -fsSL -o /work/libs/log4j-api.jar  "$base/log4j-api/${L4J_VERSION}/log4j-api-${L4J_VERSION}.jar"
COPY log4j2.xml /work/log4j2.xml
COPY ldap_canary.py /work/ldap_canary.py
COPY Driver.java /work/Driver.java
COPY gateway.py /work/gateway.py
COPY entrypoint.sh /work/entrypoint.sh
RUN chmod +x /work/entrypoint.sh
RUN javac -cp "/work/libs/*" -d /work/classes /work/Driver.java \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
CMD ["/work/entrypoint.sh"]
