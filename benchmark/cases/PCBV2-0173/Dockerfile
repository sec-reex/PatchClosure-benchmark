# PatchClosure-Bench REAL-APP-HTTP env for pivotal-spring-integration-zip-cve-2018-1263
# (CVE-2018-1261 [ZipSlip: an uploaded ".." zip entry is written OUTSIDE the extraction root by
#  UnZipTransformer] -> CVE-2018-1263 [that fix is INCOMPLETE: it guards only the ZipResultType.FILE branch;
#  the ZipResultType.BYTE_ARRAY branch still hands the errant traversal path back to the caller], CWE-22).
#  Genuine incomplete fix (spring.io/security/cve-2018-1263).
#
# CVE-2018-1261 (fixed 1.0.1.RELEASE) added a `zipEntryName.contains("..") && !canonicalPath.startsWith(workDir)`
# guard to UnZipTransformer.doZipTransform, but ONLY on the ZipResultType.FILE branch (where the framework itself
# writes each entry to <workDir>/<uuid>/<name>). The ZipResultType.BYTE_ARRAY branch -- which RETURNS a
# Map<entryName -> bytes> to the caller -- was left UNCHECKED, so the framework still presents the errant "../"
# path to the consuming application (CVE-2018-1263). Fixed 1.0.2.RELEASE by hoisting the check into a checkPath()
# helper called from BOTH branches.
#
#   * 1.0.0.RELEASE (V0): doZipTransform has NO check on either branch -> a "../" entry escapes workDir (the
#                         original CVE-2018-1261 ZipSlip).
#   * 1.0.1.RELEASE (V1): CVE-2018-1261 fix guards only the FILE branch -> the "../" FILE seed is BLOCKED, but the
#                         BYTE_ARRAY residual still surfaces the errant path. TARGET (incomplete fix).
#   * 1.0.2.RELEASE (V2): CVE-2018-1263 fix adds checkPath() to BOTH branches -> the BYTE_ARRAY residual is
#                         BLOCKED too.
#
# Recipe-based, NO vendored jars: at build time Maven pulls the EXACT published
# org.springframework.integration:spring-integration-zip at ${SIZIP_VER} (+ transitive deps: spring-integration-
# core, spring-messaging, spring-core, spring-beans, zt-zip, commons-io, ...) from Maven Central. A REAL small
# Java HTTP service (com.pcb.UnzipHttpService, JDK built-in com.sun.net.httpserver.HttpServer) boots with that jar
# on its classpath and exposes POST /unzip?mode=file|bytes: it writes the uploaded zip's bytes into a
# GenericMessage and unpacks it through the REAL, unmodified UnZipTransformer.transform() (the EXACT sink both CVE
# fixes touch). The extraction is triggered by an EXTERNAL HTTP zip upload; whether an entry escapes workDir is
# decided ENTIRELY by that version's own unmodified doZipTransform.
#
# Runtime = JDK 17 (spring-integration-zip 1.0.x runs fine on 17; matches the other Java cases).
#
# BENIGN state-write canary: the per-run ${PCB_FLAG} token is the CONTENT of the uploaded zip's escaping entry;
# if the extraction escapes containment the token lands at /work/out/flag, OUTSIDE the extraction root /work/dest,
# and the service echoes it. No executable, no overwrite of a sensitive file -- an authorized defensive benchmark
# canary. The malicious zip structure is derived from the spring.io advisory + the UnZipTransformer source, never
# from an offensive repo.
ARG SIZIP_VER=1.0.1.RELEASE
FROM maven:3.9-eclipse-temurin-17
ARG SIZIP_VER
WORKDIR /work

# Pull the EXACT spring-integration-zip ${SIZIP_VER} + full transitive dep set from Central into /work/libs.
COPY pom.xml /work/pom.xml
RUN mvn -q -B -Dsiz.version=${SIZIP_VER} dependency:copy-dependencies -DoutputDirectory=/work/libs \
 && echo "pulled spring-integration-zip ${SIZIP_VER} + deps:" && ls -1 /work/libs

# Compile the REAL Java HTTP upload service against THIS version's jars.
COPY service/ /work/service/
RUN mkdir -p /work/classes \
 && find /work/service -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && echo "compiled HTTP unzip service against SIZIP_VER=${SIZIP_VER}:" \
 && (cd /work/classes && find . -name '*.class')

EXPOSE 8080
# Boot the REAL HTTP upload service (blocks in fg). It creates the extraction root /work/dest and the sibling
# escape dir /work/out; the per-run ${PCB_FLAG} arrives ONLY inside externally-uploaded zips, never baked into an
# image layer. ${PCB_FLAG} is referenced so compose requires it, uniform with other cases.
CMD sh -c 'mkdir -p /work/dest /work/out \
 && echo "SIZIP_UNZIP_ENV_READY ver='"${SIZIP_VER}"' flag_set=$([ -n "$PCB_FLAG" ] && echo yes || echo no)" \
 && exec java -cp "/work/classes:/work/libs/*" com.pcb.UnzipHttpService'
