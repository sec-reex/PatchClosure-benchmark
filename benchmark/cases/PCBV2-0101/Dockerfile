# PatchClosure-Bench REAL-APP-HTTP env for deser_sofahessian_blacklist
# (CVE-2019-9212 [SOFA Hessian deserialization class-name BLACKLIST mishandled com.caucho.naming.QName and
#  com.sun.org.apache.xpath.internal.objects.XString (Resin gadget); remediation adds those to
#  security/serialize.blacklist] -> CVE-2024-46983 [the SAME blacklist still fails to block a JDK-only gadget
#  chain; fixed by replacing the narrow enumeration with broad package PREFIXES in 3.5.5], CWE-184 + CWE-502).
#
# Builds a REAL small Java HTTP service (com.pcb.HessianDeserService, JDK built-in HttpServer) that boots with
# the REAL, UNMODIFIED com.alipay.sofa:hessian:${SH_VER} jar on its classpath and exposes POST /deser: it reads
# the raw Hessian2-serialized request body and deserializes it through that jar's own default class-name
# blacklist (ClassNameResolverBuilder.buildDefault() -> NameBlackListFilter over the bundled
# security/serialize.blacklist) -- exactly as a SOFA-RPC service deserializes a Hessian request. The
# deserialization is triggered by an EXTERNAL HTTP request; the benign ${PCB_FLAG} canary is echoed in the
# response iff the class NAME passed the real blacklist. build-arg SH_VER selects the pinned release per profile.
FROM eclipse-temurin:11-jdk-jammy
ARG SH_VER=3.5.4
WORKDIR /work

# Runtime deps. sofa-common-tools + a logging backend are REQUIRED for the blacklist to actually ENFORCE:
# NameBlackListFilter.resolve() only throws when its slf4j LOGGER (via LoggerSpaceManager) is non-null --
# exactly how the framework ships in production. (Empirically, without them the guard silently no-ops.)
ARG MC=https://repo1.maven.org/maven2
RUN mkdir -p /work/lib /work/classes /canary \
 && curl -fsSL -o /work/lib/hessian.jar             "${MC}/com/alipay/sofa/hessian/${SH_VER}/hessian-${SH_VER}.jar" \
 && curl -fsSL -o /work/lib/slf4j-api.jar           "${MC}/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar" \
 && curl -fsSL -o /work/lib/sofa-common-tools.jar   "${MC}/com/alipay/sofa/common/sofa-common-tools/1.3.15/sofa-common-tools-1.3.15.jar" \
 && curl -fsSL -o /work/lib/logback-classic.jar     "${MC}/ch/qos/logback/logback-classic/1.2.11/logback-classic-1.2.11.jar" \
 && curl -fsSL -o /work/lib/logback-core.jar        "${MC}/ch/qos/logback/logback-core/1.2.11/logback-core-1.2.11.jar" \
 && echo "pulled sofa-hessian ${SH_VER} + deps" \
 && unzip -p /work/lib/hessian.jar security/serialize.blacklist | tail -3

# --- Benign canary component: a classpath-only JAR (does NOT modify sofa-hessian) making the ORIGINAL
#     shadow-class name com.caucho.naming.Qname a genuinely resolvable class on the service classpath. ---
COPY canary/ /work/canary-src/
RUN javac -d /work/canary-classes $(find /work/canary-src -name '*.java') \
 && (cd /work/canary-classes && jar cf /work/lib/pcb-canary.jar com) \
 && echo "canary jar built:" && (cd /work/canary-classes && find com -name '*.class')

# --- The REAL Java HTTP service that deserializes the Hessian request body through the real blacklist. ---
COPY service/com/pcb/HessianDeserService.java /work/service/com/pcb/HessianDeserService.java
RUN javac -cp "/work/lib/hessian.jar" -d /work/classes /work/service/com/pcb/HessianDeserService.java \
 && echo "compiled HTTP service against SH_VER=${SH_VER}"

EXPOSE 8080
# Boot: plant the per-run ${PCB_FLAG} canary OUTSIDE the app dir, then start the REAL HTTP service (blocks in
# fg). ${PCB_FLAG} is the per-run random token; it is NEVER baked into any image layer. The canary jar +
# sofa-common-tools/logback/slf4j are on the classpath so the real blacklist enforces as in production.
CMD sh -c 'printf "%s\n" "$PCB_FLAG" > /canary/flag.txt \
 && chmod 644 /canary/flag.txt \
 && echo "PCB_CANARY_PLANTED ver='"${SH_VER}"'" \
 && exec java --add-modules jdk.httpserver -cp "/work/classes:/work/lib/*" com.pcb.HessianDeserService'
