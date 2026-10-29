# PatchClosure-Bench REAL-SERVER env for jenkins-core-cve-2019-10384 (Jenkins CSRF crumb, CWE-352).
#
#   CVE-2019-10353 (SECURITY-626)  ->  CVE-2019-10384 (SECURITY-1491, incomplete fix).
#
# Boots the OFFICIAL, version-exact Jenkins LTS controller (2.176.1 / 2.176.2 / 2.176.3) as a
# REAL HTTP server. The CSRF-crumb bypass is triggered by EXTERNAL HTTP requests -- NOT by lifting
# hudson.security.csrf.DefaultCrumbIssuer into a harness (the previous, BANNED build did that).
#
# Configuration is done ONLY via init hooks (init.groovy.d) -- no Jenkins core source is modified
# or transcribed:
#   * 10-csrf.groovy    installs the REAL DefaultCrumbIssuer (CSRF protection ON, IP in the crumb)
#   * 20-endpoint.groovy registers a tiny crumb-guarded state-write endpoint that reveals ${PCB_FLAG}
#                        only when the REAL CrumbFilter accepts the replayed crumb.
# The per-version DefaultCrumbIssuer that ships inside each image is what differs -- that is the
# whole point (see patch.diff): V0 has no session in the crumb, V1 uses the NO_SESSION constant,
# V2 binds every crumb to a created session.
ARG JENKINS_TAG=2.176.2
FROM --platform=linux/amd64 jenkins/jenkins:${JENKINS_TAG}
# Skip the setup wizard so the controller boots straight into our init hooks.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
# Groovy init hooks run once at boot (alphabetical): 10 = CSRF issuer, 20 = reveal endpoint.
COPY --chown=jenkins:jenkins init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/
