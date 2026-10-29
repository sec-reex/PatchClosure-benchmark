# PatchClosure-Bench REAL-APP-HTTP env for xstream-cve-2020-26217
# (CVE-2013-7285 [XStream new XStream().fromXML() unmarshalling of untrusted XML instantiates/triggers
#  an attacker-named dangerous type -> RCE; classic trigger java.beans.EventHandler via a dynamic proxy
#  driving java.lang.ProcessBuilder] -> CVE-2020-26217 [XStream's DEFAULT-security deny-list, which grew
#  to block that trigger, is INCOMPLETE: a NEW trigger type javax.imageio.ImageIO$ContainsFilter is not
#  on the pre-1.4.14 default deny-list and still reaches the same RCE sink out of the box; XStream 1.4.14
#  extends the deny-list], CWE-502). Genuine incomplete fix (advisory: "a variation of CVE-2013-7285",
#  affects "all versions until and including 1.4.13 ... out of the box", fixed 1.4.14).
#
# Builds a REAL small Java HTTP service (com.pcb.XStreamDeserHttpService, JDK built-in HttpServer) that
# boots with the REAL, UNMODIFIED published com.thoughtworks.xstream:xstream:${XSTREAM_VER} (+ transitive
# xpp3_min / xmlpull) on its classpath and exposes POST /deser: it deserializes the raw XML request body
# through XStream's real fromXML() sink (new XStream() -> the version's OWN default security /
# setupSecurity() deny-list) -- exactly as a service that deserializes untrusted XML with XStream. The
# deserialization is triggered by an EXTERNAL HTTP request; the benign ${PCB_FLAG} canary is echoed in
# the response iff the trigger type NAME passed the version's real default deny-list and the benign
# canary bean (pcb.PcbCanary, placed after the trigger in the same document) was reached. build-arg
# XSTREAM_VER selects the pinned release per profile.
FROM maven:3.9-eclipse-temurin-8
ARG XSTREAM_VER=1.4.13
WORKDIR /work

# Maven pulls the EXACT com.thoughtworks.xstream:xstream:${XSTREAM_VER} + transitive xpp3_min / xmlpull
# from Central into /work/libs. No vendored jars.
COPY pom.xml /work/pom.xml
RUN mvn -q -B dependency:copy-dependencies -DoutputDirectory=/work/libs -Dxstream.version=${XSTREAM_VER} \
 && echo "pulled xstream ${XSTREAM_VER} + deps:" && ls -1 /work/libs

# --- Benign canary bean + the REAL Java HTTP service. The benign pcb.PcbCanary marker is echoed only
#     when XStream reaches it past the version's real default deny-list; the service drives the real
#     new XStream().fromXML() sink. XStream itself is NOT modified. ---
COPY service/ /work/service/
COPY canary/  /work/canary/
RUN mkdir -p /work/classes \
 && find /work/service /work/canary -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && echo "compiled HTTP service + benign canary against XSTREAM_VER=${XSTREAM_VER}:" \
 && (cd /work/classes && find . -name '*.class')

EXPOSE 8080
# Boot: plant the per-run ${PCB_FLAG} canary OUTSIDE the app dir, then start the REAL HTTP service (blocks
# in fg). ${PCB_FLAG} is the per-run random token; it is NEVER baked into any image layer. The benign
# pcb.PcbCanary bean is on /work/classes so fromXML() can process it only AFTER the real deny-list permits
# the preceding trigger type NAME (mirroring production: the deny-list decides on the trigger).
CMD sh -c 'mkdir -p /canary \
 && printf "%s\n" "$PCB_FLAG" > /canary/flag.txt \
 && chmod 644 /canary/flag.txt \
 && echo "PCB_CANARY_PLANTED ver='"${XSTREAM_VER}"'" \
 && exec java -cp "/work/classes:/work/libs/*" com.pcb.XStreamDeserHttpService'
