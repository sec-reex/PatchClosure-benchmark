# PatchClosure-Bench REAL-SERVER env for jenkins-cve-2025-31721
#   CVE-2025-27622 (SECURITY-3495)  ->  CVE-2025-31721 (SECURITY-3513, incomplete fix).
#
# Boots the OFFICIAL, version-exact Jenkins LTS controller (2.492.1 / 2.492.2 / 2.492.3)
# as a REAL HTTP server. The auth-bypass is triggered by an EXTERNAL HTTP request from a
# low-privilege user -- NOT by lifting core Java and NOT by `docker compose exec`.
#
# Configuration is done ONLY via init hooks (init.groovy.d) + the standard matrix-auth
# plugin -- no Jenkins core source is modified or transcribed:
#   * a private security realm with two accounts: admin / attacker
#   * matrix authorization: attacker holds Overall/Read + Agent/Create + Agent/ExtendedRead
#     but NOT Agent/Configure  (exactly the predicate in advisory 2025-04-02)
#   * a permanent agent "agentA" whose config.xml carries a GENUINE hudson.util.Secret
#     (the version-exact controller encrypts ${PCB_FLAG} at boot; plaintext never on disk/image)
ARG JENKINS_TAG=2.492.2-lts
FROM jenkins/jenkins:${JENKINS_TAG}
USER root
# Skip the setup wizard so the controller boots straight into our init hooks.
# runSetupWizard=false -> boot straight into init hooks.
# ExtendedReadPermission=true -> enable the grantable Agent/ExtendedRead permission (OFF by
#   default; without it Jenkins requires Agent/Configure to read config.xml, collapsing the
#   low-priv predicate this case depends on). This is the exact permission named in advisory
#   2025-03-05 (CVE-2025-27622) and re-checked by CVE-2025-31720 on the copy source.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.security.ExtendedReadPermission=true"
# matrix-auth gives us the fine-grained Agent/Create-without-Agent/Configure predicate.
# Pinned to a release compatible with the 2.492.x core line.
RUN jenkins-plugin-cli --latest false --plugins matrix-auth:3.2.4
USER jenkins
# Groovy init hooks run once at boot (alphabetical): 10 = security, 20 = seeded agent.
COPY init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/
