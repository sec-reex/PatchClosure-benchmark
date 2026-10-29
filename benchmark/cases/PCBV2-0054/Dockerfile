# PatchClosure-Bench REAL-SERVER-TCP env for apache-dubbo-serializer-switch-cve-2021-25641
# (CVE-2020-1948 [Apache Dubbo provider Hessian2 deserialization of untrusted RPC args -> RCE] ->
#  CVE-2021-25641 [the CVE-2020-1948 hessian2 type-ALLOWLIST is INCOMPLETE: an attacker flips the
#  Dubbo frame's serialization-id byte to native-hessian (id 10), a serializer that does NOT consult
#  the hessian2 allowlist, routing around it; 2.7.12 + serialization.security.check closes the
#  switch], CWE-502).
#
# Dubbo is a NETWORK RPC framework: its real usage is a provider listening on a dubbo:// TCP port. This
# image builds a REAL, UNMODIFIED Dubbo provider (app/Provider.java) that exports DemoService on
# 0.0.0.0:20880 with NO registry, plus the attacker consumer (app/Client.java) and the benign shadow
# bean com.pcb.PcbFlagProbe. Maven pulls the EXACT org.apache.dubbo:dubbo:${DUBBO_VER} (which shades the
# per-version hessian-lite) + dubbo-serialization-native-hession from Central. No Dubbo code is edited.
#
# The SAME image serves two roles (selected by the container command, like the MINA/Netty real-server
# cases): the version services run `java ... com.pcb.Provider` (the REAL provider TCP server); the
# SEPARATE `client` service runs `java -Dpcb.role=client ... com.pcb.Client <host> 20880 <serializer>`,
# connecting to the provider over the REAL docker network -- a genuine external network trigger.
#
# Source-verified guard lineage (upstream tags):
#   * dubbo 2.7.6 (V0): hessian-lite 3.2.6 has NO ClassFactory -> a hessian2 arg naming
#                       com.pcb.PcbFlagProbe is instantiated -> flag read.
#   * dubbo 2.7.8 (V1 = CVE-2020-1948 fix, TARGET): hessian-lite 3.2.8 ADDS ClassFactory + Dubbo adds
#                       WhitelistHessian2FactoryInitializer (opt-in via -Ddubbo.application.hessian2
#                       .whitelist=true). With whitelist on, ClassFactory.load() allows only "java.*"
#                       and returns HashMap for anything else -> the hessian2 (id 2) PcbFlagProbe arg
#                       is BLOCKED. INCOMPLETE: native-hessian (id 10) uses com.caucho.hessian, NOT
#                       hessian-lite, so it skips the ClassFactory; and 2.7.8 has NO checkSerialization
#                       -> the SAME probe over id 10 is instantiated (residual reaches).
#   * dubbo 2.7.12 (V2 = CVE-2021-25641 fix): CodecSupport.checkSerialization (opt-in via
#                       -Dserialization.security.check=true) rejects a network serialization id that
#                       != the server's configured id BEFORE args are deserialized -> the id-10 switch
#                       is BLOCKED; the hessian2 original stays blocked by the whitelist.
FROM maven:3.8-eclipse-temurin-8
ARG DUBBO_VER=2.7.8
WORKDIR /work
COPY pom.xml /work/pom.xml
COPY app/ /work/app/
# Resolve the EXACT dubbo ${DUBBO_VER} + deps from Central into /work/libs.
RUN mvn -q -B dependency:copy-dependencies -DoutputDirectory=/work/libs -Ddubbo.version=${DUBBO_VER}
# Compile the benign service + shadow bean + provider/client against the real dubbo jars.
RUN mkdir -p /work/classes \
 && find /work/app -name '*.java' > /work/sources.txt \
 && javac -cp "/work/libs/*" -d /work/classes @/work/sources.txt \
 && printf '/work/classes:/work/libs/*' > /work/cp.txt
# Default (version services): plant the rce-oob canary OUTSIDE the app dir at RUNTIME, then run the REAL
# Dubbo provider. DUBBO_PROPS (per profile) enables the version's guards: whitelist on V1/V2,
# security-check on V2. (The `client` service overrides this command to run Client instead; it never
# plants a canary and stays silent via -Dpcb.role=client.)
# Small heap: the maven JDK image's default ergonomics can grab ~1/4 host RAM and
# OOM-kill the provider after PROVIDER_READY (v1 verify then sees "not running").
CMD ["sh","-c","mkdir -p /canary && printf '%s\\n' \"$PCB_FLAG\" > /canary/flag.txt && chmod 644 /canary/flag.txt && exec java -Xms32m -Xmx384m -XX:+UseSerialGC $DUBBO_PROPS -Djava.net.preferIPv4Stack=true -Ddubbo.application.qos.enable=false -cp \"$(cat /work/cp.txt)\" com.pcb.Provider"]
