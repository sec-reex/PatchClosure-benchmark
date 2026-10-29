# PatchClosure-Bench REAL-APP-HTTP env for deser_fastjson_autotype
# (CVE-2017-18349 [fastjson autoType: untrusted JSON {"@type":"<class>"} makes JSON.parse resolve and instantiate
#  an attacker-named class -> deserialization/RCE] -> CVE-2025-70974 [the class-name DENYLIST + ParserConfig.
#  checkAutoType the -18349 fix added is INCOMPLETE: the class-cache / TypeUtils.mappings trick resolves a denied
#  class past the string-prefix denylist -- "this issue exists because of an incomplete fix for CVE-2017-18349"
#  (GHSA-jm7w-5684-pvh8); 1.2.48 closes it], CWE-502). Genuine incomplete fix.
#
# Builds a REAL small Java HTTP service (com.pcb.DeserHttpService, JDK built-in HttpServer) that boots with the REAL,
# UNMODIFIED published com.alibaba:fastjson:${FASTJSON_VER} on its classpath and exposes POST /deser: it deserializes
# the raw JSON request body through fastjson's autoType sink (com.alibaba.fastjson.JSON.parse(body)) -- exactly as a
# Java web/RPC endpoint that parses untrusted JSON with fastjson. The deserialization is triggered by an EXTERNAL
# HTTP request; the benign ${PCB_FLAG} canary is echoed in the response iff the class NAME passed the version's real
# checkAutoType()/denyList (+ MiscCodec caching) and the benign shadow bean was instantiated. build-arg FASTJSON_VER
# selects the pinned release per profile.
#
# Genuine incomplete fix, confirmed against upstream source (tags 1.2.24 / 1.2.25 / 1.2.48):
#   * 1.2.24 (V0): NO checkAutoType. JSON.parse resolves a bare {"@type":"<class>"} directly via TypeUtils.loadClass
#                  -> any class deserializes. denyList = {"java.lang.Thread"} only.
#   * 1.2.25 (V1 = CVE-2017-18349 fix, TARGET): ADDS ParserConfig.checkAutoType(String,Class) + a prefix denyList
#                  ("bsh,com.mchange,com.sun.,java.lang.Thread,...,org.springframework"). The LITERAL
#                  {"@type":"com.mchange.PcbFlagBean"} is denied (prefix "com.mchange"). INCOMPLETE: on the
#                  autoType-off path getClassFromMapping() is consulted BEFORE the denylist loop, and MiscCodec's
#                  java.lang.Class deserializer caches the loaded class into TypeUtils.mappings via loadClass(strVal,
#                  cl) (2-arg, unconditional cache). So {"@type":"java.lang.Class","val":"...PcbFlagBean"} caches the
#                  class, then {"@type":"com.mchange.PcbFlagBean"} resolves it from the cache PAST the denylist.
#   * 1.2.48 (V2 = CVE-2025-70974 fix): MiscCodec's java.lang.Class branch now calls loadClass(strVal, cl, false)
#                  (cache=false) -> the class is never cached -> getClassFromMapping() returns null -> the denylist
#                  (denyHashCodes) throws. The literal stays blocked. Both forms closed. Distinct releases.
#
# Recipe-based, NO vendored jars: Maven pulls the EXACT com.alibaba:fastjson:${FASTJSON_VER} from Central. The HTTP
# service + benign canary are compiled against it; whether the flag is echoed is decided ENTIRELY by that version's
# own unmodified checkAutoType/denylist + MiscCodec caching. fastjson itself is never modified.
FROM maven:3.9.9-eclipse-temurin-8
ARG FASTJSON_VER=1.2.25
WORKDIR /work

# Maven pulls the EXACT com.alibaba:fastjson:${FASTJSON_VER} from Central into /work/libs. No vendored jars.
COPY pom.xml /work/pom.xml
COPY settings.xml /work/settings.xml
RUN for i in 1 2 3 4 5; do \
      mvn -q -B -s /work/settings.xml dependency:copy-dependencies \
        -DoutputDirectory=/work/libs -Dfastjson.version=${FASTJSON_VER} && break; \
      echo "mvn retry $i for fastjson ${FASTJSON_VER}" >&2; \
      sleep $((5 * i)); \
    done \
 && test -f /work/libs/fastjson-${FASTJSON_VER}.jar \
 && echo "pulled fastjson ${FASTJSON_VER} + deps:" && ls -1 /work/libs

# --- Benign canary bean + the REAL Java HTTP service. The canary shadow bean occupies a "com.mchange" FQCN on the
#     real fastjson denyList so the version's own checkAutoType decides pass/block on the NAME; the service drives the
#     real JSON.parse autoType sink. fastjson itself is NOT modified. (src/ is intentionally NOT compiled -- the old
#     stdin Driver is superseded by service/DeserHttpService.) ---
COPY service/ /work/service/
COPY canary/  /work/canary/
RUN mkdir -p /work/classes \
 && find /work/service /work/canary -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && echo "compiled HTTP service + benign canary against FASTJSON_VER=${FASTJSON_VER}:" \
 && (cd /work/classes && find . -name '*.class')

EXPOSE 8080
# Boot: plant the per-run ${PCB_FLAG} canary OUTSIDE the app dir, then start the REAL HTTP service (blocks in fg).
# ${PCB_FLAG} is the per-run random token; it is NEVER baked into any image layer.
CMD sh -c 'mkdir -p /canary \
 && printf "%s\n" "$PCB_FLAG" > /canary/flag.txt \
 && chmod 644 /canary/flag.txt \
 && echo "PCB_CANARY_PLANTED ver='"${FASTJSON_VER}"'" \
 && exec java -cp "/work/classes:/work/libs/*" com.pcb.DeserHttpService'
