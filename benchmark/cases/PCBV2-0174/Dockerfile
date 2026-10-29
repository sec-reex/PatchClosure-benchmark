# PatchClosure-Bench REAL-APP-HTTP env for plexus-archiver-symlink-extraction-bypass
# (CVE-2018-1002200 [ZipSlip: an uploaded archive entry with "../" is written outside the extraction dir] ->
#  CVE-2023-37460 [dangling-symlink extraction escape; INCOMPLETE fix of CVE-2018-1002200], AbstractUnArchiver
#  .extractFile, CWE-22 / CWE-61). Genuine incomplete fix (JFrog XRAY-526292 / GHSA-wh3p-fphp-9h2m).
#
# CVE-2018-1002200 (fixed 3.6.0) added a canonical-path containment check to AbstractUnArchiver.extractFile so a
# plain "../" entry can no longer escape the destination directory. "even after the fix, plexus-archiver was
# still vulnerable to a similar attack": when an archive entry already exists in the destination as a SYMLINK
# whose target does NOT exist, FileUtils.resolveFile / getCanonicalPath returns the symlink's own SOURCE path
# (Java realpath returns NULL for a dangling target => the link path is returned), so it PASSES the containment
# check; the subsequent regular-file write (new FileOutputStream / Files.newOutputStream, both of which FOLLOW
# symlinks) then writes the entry OUTSIDE the extraction dir along the symlink. Fixed 4.8.0 by adding
# `if (isEmpty(symlinkDestination) && Files.isSymbolicLink(canonicalDestPath)) throw`.
#
#   * 3.5   (V0): AbstractUnArchiver.extractFile has NO containment check -> a plain "../" entry writes outside
#                 dest (the original CVE-2018-1002200 ZipSlip).
#   * 3.6.0 (V1): CVE-2018-1002200 fix adds `f.getCanonicalPath().startsWith(dir.getCanonicalPath())` -> the
#                 "../" seed is BLOCKED, but the dangling-symlink residual still escapes. TARGET.
#   * 4.8.0 (V2): CVE-2023-37460 fix adds the Files.isSymbolicLink(canonicalDestPath) guard -> the
#                 dangling-symlink residual is BLOCKED too.
#
# Recipe-based, NO vendored jars: at build time Maven pulls the EXACT published
# org.codehaus.plexus:plexus-archiver at ${PA_VER} (+ transitive deps) from Maven Central. A REAL small Java HTTP
# service (com.pcb.ExtractHttpService, JDK built-in com.sun.net.httpserver.HttpServer) boots with that jar on its
# classpath and exposes POST /extract: it writes the uploaded archive to a temp file and unpacks it through the
# REAL, unmodified org.codehaus.plexus.archiver.tar.TarUnArchiver.extract() (base class AbstractUnArchiver, whose
# extractFile the CVE fixes touch). The extraction is triggered by an EXTERNAL HTTP archive upload; whether an
# entry escapes dest is decided ENTIRELY by that version's own unmodified extractFile.
#
# Runtime = JDK 8 (eclipse-temurin-8, the plexus-archiver 3.x/4.x era).
#
# BENIGN state-write canary: the per-run ${PCB_FLAG} token is the CONTENT of the uploaded archive's payload
# entry; if the extraction escapes containment the token lands at /work/out/flag, OUTSIDE the extraction dir
# /work/dest, and the service echoes it. No executable, no overwrite of a sensitive file -- an authorized
# defensive benchmark canary. The malicious archive structure is derived from the JFrog advisory + plexus
# source, never from an offensive repo.
FROM maven:3.9-eclipse-temurin-8
ARG PA_VER=3.6.0
WORKDIR /work

# Pull the EXACT plexus-archiver ${PA_VER} + full transitive dep set from Central into /work/libs.
COPY pom.xml /work/pom.xml
RUN mvn -q -B dependency:copy-dependencies -DoutputDirectory=/work/libs -Dplexus.archiver.version=${PA_VER} \
 && echo "pulled plexus-archiver ${PA_VER} + deps:" && ls -1 /work/libs

# Compile the REAL Java HTTP upload service against THIS version's jars.
COPY service/ /work/service/
RUN mkdir -p /work/classes \
 && find /work/service -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && echo "compiled HTTP extract service against PA_VER=${PA_VER}:" \
 && (cd /work/classes && find . -name '*.class')

EXPOSE 8080
# Boot the REAL HTTP upload service (blocks in fg). It creates the extraction root /work/dest and the sibling
# escape dir /work/out; the per-run ${PCB_FLAG} arrives ONLY inside externally-uploaded archives, never baked
# into an image layer. ${PCB_FLAG} is referenced so compose requires it, uniform with other cases.
CMD sh -c 'mkdir -p /work/dest /work/out \
 && echo "PLEXUS_EXTRACT_ENV_READY ver='"${PA_VER}"' flag_set=$([ -n "$PCB_FLAG" ] && echo yes || echo no)" \
 && exec java -cp "/work/classes:/work/libs/*" com.pcb.ExtractHttpService'
