# PatchClosure-Bench REAL-Spring-Boot-app env for ssti_thymeleaf_spel_sandbox
# (CVE-2026-40478 [Thymeleaf restricted/sandboxed SpEL: `new<TAB>Class` bypasses the `new`-keyword
#  scanner -> object instantiation -> SSTI] -> CVE-2026-41901 [the 3.1.4 fix normalizes whitespace but
#  still scans CASE-SENSITIVELY for lowercase "new"; UPPERCASE `NEW` (SpEL matches the operator
#  case-insensitively) still escapes -- "improper recognition of unauthorized syntax patterns"; 3.1.5
#  lowercases before scanning], CWE-94 / CWE-917). Genuine incomplete fix.
#
# Source-verified guard evolution in the SHARED string keyword scanner reached from the restricted
# SpEL sink (SpringStandardExpressionUtils.containsExternalAccess() + ExpressionUtils.normalize()):
#   * 3.1.3 (V0): normalize() strips control chars, so `new<TAB>Class` collapses to `newClass` and the
#                 scanner (which requires whitespace after "new") misses it -> `new<TAB>` escapes.
#   * 3.1.4 (V1 = CVE-2026-40478 fix, TARGET): normalize() maps every whitespace char to a plain space,
#                 so `new<TAB>` -> `new ` -> detected -> BLOCKED. INCOMPLETE: normalize() does NOT
#                 lowercase and the scanner matches literal lowercase "new"; UPPERCASE `NEW` is not
#                 recognized yet SpEL still parses it as the instantiation operator -> `NEW ` escapes.
#   * 3.1.5 (V2 = CVE-2026-41901 fix): normalize(exp, true) lowercases before scanning -> `NEW ` ->
#                 "new " -> detected -> BLOCKED. Both forms closed. Distinct releases / distinct commits.
#
# Recipe-based, NO vendored jars: Maven pulls the EXACT thymeleaf-spring6 ${THYMELEAF_VER} (+ matching
# thymeleaf core) from Central by overriding the Spring-Boot-managed thymeleaf.version. The app is a
# REAL Spring Boot MVC web app on embedded Tomcat; whether the flag is read is decided entirely by that
# version's own unmodified containsExternalAccess()/normalize() keyword scanner reached over HTTP.
#
# BENIGN read-exfil canary: pcb.PcbFlagReader (package "pcb" is on NO Thymeleaf blocklist at any
# version) reads ${PCB_FLAG} from /flag in its no-arg CONSTRUCTOR and renders it -- so the flag
# surfaces only when the version's scanner LETS the restricted context run `new pcb.PcbFlagReader()`.
# No gadget chain, no reflection, no command execution; the payload carries only a `new` expression.

# ---- build stage: compile + repackage the fat jar with the pinned thymeleaf ----
FROM maven:3.9-eclipse-temurin-17 AS build
ARG THYMELEAF_VER=3.1.4.RELEASE
WORKDIR /build
COPY pom.xml .
COPY src ./src
# -Dthymeleaf.version overrides the Spring-Boot-managed property so the EXACT published
# thymeleaf-spring6 ${THYMELEAF_VER} (+ transitive thymeleaf core) is what gets pulled from Central.
RUN mvn -q -B -DskipTests -Dthymeleaf.version=${THYMELEAF_VER} package

# ---- run stage: boot the app on a JRE ----
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /build/target/app.jar /app/app.jar
EXPOSE 80
# Plant the read-exfil canary OUTSIDE the app at RUNTIME, then boot the real Spring Boot web server.
CMD ["sh","-c","printf '%s' \"$PCB_FLAG\" > /flag && chmod 644 /flag && exec java -jar /app/app.jar"]
