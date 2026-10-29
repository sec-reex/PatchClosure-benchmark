# PatchClosure-Bench REAL-SERVER-TCP env for deser_jenkins_remoting
# (CVE-2015-8103 [Jenkins remoting CLI Java deserialization -> RCE; the fix ADDS the hudson.remoting
#  ClassFilter blacklist of dangerous classes, applied in ObjectInputStreamEx.resolveClass()] ->
#  CVE-2017-1000353 [a serialized java.security.SignedObject is deserialized by the remoting deser sink,
#  and SignedObject.getObject() reconstructs its signed payload using a NEW, PLAIN ObjectInputStream that
#  is NOT wrapped by the ClassFilter, so the blacklist is bypassed; the fix ADDS java.security.SignedObject
#  to the blacklist], CWE-502).
#
# hudson.remoting is a NETWORK channel framework: its real usage is a TCP channel between two JVMs. This
# image builds a REAL remoting TCP server (Server.java) that binds a ServerSocket and reads each incoming
# object off the socket through the REAL, UNMODIFIED hudson.remoting.ObjectInputStreamEx(in, cl) sink
# (exactly the 2-arg CLI Command#readFrom form -> ClassFilter.DEFAULT on remoting 2.53+). An EXTERNAL TCP
# client (Client.java, run as a separate container) drives it over the network. No remoting code is edited;
# the REAL, unmodified published remoting:${REMOTING_VER} handles resolveClass()/ClassFilter.
#
# Source-verified (github.com/jenkinsci/remoting, per tag):
#   * hudson.remoting.ClassFilter is ABSENT at remoting-2.52 and INTRODUCED at remoting-2.53
#     ([SECURITY-218] "be careful what we unmarshal from network", 2015-11-06 == CVE-2015-8103 fix).
#     ObjectInputStreamEx.resolveClass():
#         2.52:  return Class.forName(name, false, cl);                            // NO filter
#         2.53:  return filter.check(Class.forName(filter.check(name), false, cl)); // ClassFilter.DEFAULT
#   * The 2.53 ClassFilter.DEFAULT blacklist = { org.codehaus.groovy.runtime.*,
#     org.apache.commons.collections.functors.*, *org.apache.xalan* }  -- NO java.security.SignedObject.
#   * remoting-3.16 is the FIRST remoting release whose own ClassFilter.DEFAULT adds
#     "^java[.]security[.]SignedObject$" (JEP-200 consolidation of the CVE-2017-1000353 SignedObject block;
#     the SECURITY-429 fix of 2017-04-26 / Jenkins 2.57 / LTS 2.46.2 added it Jenkins-core-side). It still
#     blacklists org.apache.commons.collections.functors.*.
#
# maven pulls the EXACT org.jenkins-ci.main:remoting:${REMOTING_VER} jar from the official Jenkins repo
# (pom.xml repository jenkins-public); a REAL remoting TCP server + external TCP client + benign canary are
# compiled against it. NO vendored jars.
#
# BENIGN rce-oob canary: at container start ${PCB_FLAG} (a random per-run token, absent from source) is
# written to /canary/flag.txt OUTSIDE the app dir. SUCCESS = PcbSeed.readObject reads it (only possible
# after reconstruction past the ClassFilter) and the server echoes it back over TCP. No gadget chain, no
# command execution, no persistence.
FROM maven:3.9-eclipse-temurin-8
ARG REMOTING_VER=2.53
WORKDIR /work
COPY pom.xml /work/pom.xml
COPY app/ /work/app/
# Pull the EXACT published remoting:${REMOTING_VER} jar (single artifact; the sink classes ObjectInputStreamEx
# + ClassFilter are self-contained) from repo.jenkins-ci.org via maven into /work/libs.
RUN mvn -q -B org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
      -Dartifact=org.jenkins-ci.main:remoting:${REMOTING_VER}:jar \
      -DoutputDirectory=/work/libs -Dmdep.stripVersion=true \
 && ls -l /work/libs
# Compile the REAL remoting TCP server + external client + benign canary classes against the real remoting jar.
RUN mkdir -p /work/classes \
 && javac -cp "/work/libs/*" -d /work/classes $(find /work/app -name '*.java') \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
# Default: plant the rce-oob canary OUTSIDE the app dir at RUNTIME, then run the REAL remoting TCP server.
# (The `client` service overrides this command to run Client instead; it never plants a canary.)
CMD ["sh","-c","mkdir -p /canary && printf '%s\\n' \"$PCB_FLAG\" > /canary/flag.txt && chmod 644 /canary/flag.txt && exec java -cp \"$(cat /work/cp.txt)\" Server 9009"]
