# PatchClosure-Bench REAL-APP env for deser_ofbiz_xmlrpc
# Builds and boots the REAL Apache OFBiz (one release per build-arg OFBIZ_VER) and exposes its real,
# unauthenticated XML service-engine endpoint over HTTP. The deserialization sink is OFBiz's own
# XmlSerializer <cus-obj> path (org.apache.ofbiz.service.engine.SoapSerializer -> XmlSerializer ->
# UtilObject.getObject -> org.apache.ofbiz.base.util.SafeObjectInputStream), reached unauthenticated via
# POST /webtools/control/SOAPService. NO OFBiz source is copied or modified; only a tiny benign canary JAR
# is added to the deployment classpath (plugins/pcbcanary/lib) so the real filter can resolve the benign
# shadow-class NAMES. CWE-502; CVE-2021-26295 (17.12.06) -> CVE-2021-30128 (17.12.07).
FROM eclipse-temurin:8-jdk-jammy

ARG OFBIZ_VER=17.12.06
ENV OFBIZ_VER=${OFBIZ_VER}
ENV GRADLE_OPTS="-Dorg.gradle.daemon=false"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
# Clone the REAL Apache OFBiz at the exact release tag (no vendored source in the case dir).
RUN git clone --depth 1 --branch release${OFBIZ_VER} \
        https://github.com/apache/ofbiz-framework.git ofbiz
# Repo fix: OFBiz 17.12.05's build.gradle resolves buildscript/plugin deps from jcenter.bintray.com,
# which was shut down in 2021. Redirect to mavenCentral + the Gradle Plugin Portal (no-op for 06/07,
# which already migrated off jcenter). This does not touch any OFBiz Java source.
# 17.12.05 lists only jcenter(); replace it with mavenCentral + the Gradle Plugin Portal + the same extra
# repositories that 17.12.06/07 added during their jcenter->mavenCentral migration (Red Hat GA hosts
# apache-xerces:xercesImpl:2.9.1; restlet + atlassian host other artifacts not on mavenCentral). No-op on
# 06/07, which already migrated.
RUN sed -i 's|jcenter()|mavenCentral(); maven { url "https://plugins.gradle.org/m2/" }; maven { url "https://maven.repository.redhat.com/ga/" }; maven { url "https://maven.restlet.talend.com" }; maven { url "https://packages.atlassian.com/maven-3rdparty" }|g' /opt/ofbiz/build.gradle
# Dep fix: org.jdom (JDOM 1) is imported by applications/product but, resolving via mavenCentral instead
# of the retired jcenter, it is no longer pulled onto the COMPILE classpath (only runtime, transitively).
# Add it explicitly as a compile dependency so OFBiz compiles. (jdom 1.1.3 == the org.jdom.* API OFBiz uses.)
RUN sed -i "/runtime 'org.apache.derby:derby:10.14.1.0'/a\\    compile 'org.jdom:jdom:1.1.3'" /opt/ofbiz/build.gradle \
 && grep -n "org.jdom:jdom" /opt/ofbiz/build.gradle
# 17.12.05-only: two deps whose SpringSource/Atlassian-repackaged transitives are gone from live repos.
# Align them to the exact versions 17.12.06/07 use (which resolve from the repos added above) -- same
# library line, build-environment fix only. No-op on 06/07. Does NOT touch OFBiz Java source or the sink.
RUN sed -i "s|com.springsource.com.sun.syndication:0.9.0|com.springsource.com.sun.syndication:1.0.0|; s|net.fortuna.ical4j:ical4j:1.0-rc3-atlassian-11|net.fortuna.ical4j:ical4j:1.0-rc4-atlassian-12|" /opt/ofbiz/build.gradle
# 17.12.05 imports edu.emory.mathcs.backport.java.util.* (backport-util-concurrent) in a few classes;
# 17.12.06 migrated those to java.util and dropped the (previously transitive) jar. Re-add it as a compile
# dep so 17.12.05 compiles. On mavenCentral; no-op effect on 06/07. Not an OFBiz-source edit.
RUN sed -i "/runtime 'org.apache.derby:derby:10.14.1.0'/a\\    compile 'backport-util-concurrent:backport-util-concurrent:3.1'" /opt/ofbiz/build.gradle

# --- Benign canary component: a classpath-only JAR (does NOT modify OFBiz source) ---
COPY canary/ /opt/canary/
RUN mkdir -p /opt/ofbiz/plugins/pcbcanary/lib /opt/cc \
 && cp /opt/canary/ofbiz-component.xml /opt/ofbiz/plugins/pcbcanary/ofbiz-component.xml \
 && javac -d /opt/cc $(find /opt/canary -name '*.java') \
 && (cd /opt/cc && jar cf /opt/ofbiz/plugins/pcbcanary/lib/pcb-canary.jar com) \
 && echo "canary jar built:" && (cd /opt/cc && find com -name '*.class')

WORKDIR /opt/ofbiz
# Compile OFBiz and load minimal (seed) data into the embedded Derby DB at IMAGE-BUILD time, so
# `docker compose up` only has to boot. This is the heavy step (gradle dist + deps + compile + derby load).
RUN for attempt in 1 2 3 4 5; do echo "=== Gradle attempt $attempt ==="; ./gradlew --no-daemon "ofbiz --load-data readers=seed,seed-initial" > /opt/load.log 2>&1 && break; sleep 5; done \
 || (echo '==== load.log tail ===='; tail -80 /opt/load.log; exit 1)
RUN echo "seed load done for ${OFBIZ_VER}" && grep -c 'Beginning the Data Load' /opt/load.log || true

EXPOSE 8080 8443
# Boot: plant the per-run ${PCB_FLAG} canary OUTSIDE the app dir, then start the REAL OFBiz (blocks in fg).
CMD mkdir -p /canary \
 && printf '%s' "${PCB_FLAG}" > /canary/flag.txt \
 && : > /canary/echo.txt \
 && chmod 666 /canary/flag.txt /canary/echo.txt \
 && echo "PCB_CANARY_PLANTED ver=${OFBIZ_VER}" \
 && ./gradlew --no-daemon ofbiz
