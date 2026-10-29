# PatchClosure-Bench REAL-APP-HTTP env for jackson-databind-cve-2017-17485
# (CVE-2017-7525 [jackson-databind default-typing / polymorphic deserialization of untrusted JSON
#  ["<class>", {..}] instantiates an attacker-chosen class -> RCE; the -7525 fix adds the
#  BeanDeserializerFactory.checkIllegalTypes / DEFAULT_NO_DESER_CLASS_NAMES class-name blacklist,
#  extended by CVE-2017-15095] -> CVE-2017-17485 [that enumerated blacklist is STILL INCOMPLETE: the
#  Spring application-context gadget names (FileSystemXmlApplicationContext / ClassPathXmlApplicationContext)
#  are not covered, so on 2.9.3 they still deserialize -> RCE; 2.9.4 adds Spring-specific handling via
#  SubTypeValidator.validateSubType, databind#1855], CWE-502). Genuine incomplete fix.
#
# Source-verified guard lineage:
#   * 2.8.8 (V0): BeanDeserializerFactory has NO blacklist -> any class deserializes.
#   * 2.9.3 (V1): guard = BeanDeserializerFactory.checkIllegalTypes(), an EXACT fully-qualified-NAME match
#                 against DEFAULT_NO_DESER_CLASS_NAMES (the CVE-2017-7525 #1599 set + CVE-2017-15095
#                 #1680/#1737 extension -- incl. commons-collections InvokerTransformer). NO *ApplicationContext
#                 name and NO Spring superclass handling. == -7525 + -15095 fixes, still INCOMPLETE for -17485.
#   * 2.9.4 (V2): guard = SubTypeValidator.validateSubType() (databind#1855). Keeps the exact-name set AND, for
#                 any concrete "org.springframework." class, walks the superclass chain and rejects if an
#                 ancestor's SIMPLE name is "AbstractApplicationContext" (or "AbstractPointcutAdvisor").
#                 == CVE-2017-17485 fix. Distinct release / distinct commit.
#
# Builds a REAL small Java HTTP REST service (com.pcb.DeserHttpService, JDK built-in HttpServer) that boots
# with the REAL, UNMODIFIED published com.fasterxml.jackson.core:jackson-databind:${JACKSON_VER} (+ transitive
# jackson-core / jackson-annotations) on its classpath and exposes POST /deser: it deserializes the raw JSON
# request body through jackson's default-typing sink (ObjectMapper.enableDefaultTyping(); readValue(body,
# Object.class)) -- exactly as a REST service that deserializes untrusted JSON with default typing enabled. The
# deserialization is triggered by an EXTERNAL HTTP request; the benign ${PCB_FLAG} canary is echoed in the
# response iff the class NAME passed the version's real guard and a benign shadow-class was instantiated.
# build-arg JACKSON_VER selects the pinned release per profile.
FROM maven:3.9-eclipse-temurin-8
ARG JACKSON_VER=2.9.3
WORKDIR /work

# Maven pulls the EXACT com.fasterxml.jackson.core:jackson-databind:${JACKSON_VER} + transitive
# jackson-core / jackson-annotations from Central into /work/libs. No vendored jars.
COPY pom.xml /work/pom.xml
RUN mvn -q -B dependency:copy-dependencies -DoutputDirectory=/work/libs -Djackson.version=${JACKSON_VER} \
 && echo "pulled jackson-databind ${JACKSON_VER} + deps:" && ls -1 /work/libs

# --- Benign canary component + the REAL Java HTTP service. The canary shadow beans occupy the exact FQCNs
#     the real guard reasons about (original = a blacklisted name; residual = the Spring app-context name that
#     extends a benign AbstractApplicationContext) so the real, unmodified jackson guard decides pass/block on
#     the NAME (and, on 2.9.4, the superclass chain); the service drives the real ObjectMapper default-typing
#     readValue() sink. jackson-databind itself is NOT modified. ---
COPY service/ /work/service/
COPY canary/  /work/canary/
RUN mkdir -p /work/classes \
 && find /work/service /work/canary -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && echo "compiled HTTP service + benign canary against JACKSON_VER=${JACKSON_VER}:" \
 && (cd /work/classes && find . -name '*.class')

EXPOSE 8080
# Boot: plant the per-run ${PCB_FLAG} canary OUTSIDE the app dir, then start the REAL HTTP REST service (blocks
# in fg). ${PCB_FLAG} is the per-run random token; it is NEVER baked into any image layer. The benign shadow
# beans (org.apache.commons.collections.functors.InvokerTransformer,
# org.springframework.context.support.FileSystemXmlApplicationContext extends ...AbstractApplicationContext)
# are on /work/classes so the real guard enforces on their NAME / superclass chain as in production.
CMD sh -c 'mkdir -p /canary \
 && printf "%s\n" "$PCB_FLAG" > /canary/flag.txt \
 && chmod 644 /canary/flag.txt \
 && echo "PCB_CANARY_PLANTED ver='"${JACKSON_VER}"'" \
 && exec java -cp "/work/classes:/work/libs/*" com.pcb.DeserHttpService'
