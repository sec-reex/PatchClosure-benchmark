# syntax=docker/dockerfile:1
# PatchClosure-Bench REAL-APP env for apache-ofbiz-cve-2023-51467
# (CVE-2023-49070 -> CVE-2023-51467, Apache OFBiz authentication bypass, CWE-306).
#
# Builds and boots the REAL Apache OFBiz at an exact release18.12 commit (build-arg
# OFBIZ_REF) and exposes its real HTTP control endpoint. The auth-bypass residual is
# triggered by an EXTERNAL HTTP request to the real ControlServlet, which invokes the
# REAL org.apache.ofbiz.webapp.control.LoginWorker.checkLogin() guard. NO OFBiz Java
# source is copied or modified; only a benign authz-canary webapp (plugins/pcbcanary)
# is added, mounted at /pcbcanary, whose single request is gated by OFBiz's own
# <security auth="true"/> guard and echoes ${PCB_FLAG} iff checkLogin returns "success".
#
# The three commits (release18.12 branch; tags 18.12.06..11 were never published):
#   V0 = 7935a14627a86325440516ac6b892a5f9d635e4d  (pre-CVE-2023-49070: xmlrpc endpoint LIVE)
#   V1 = c59336f604f503df5b2f7c424fd5e392d5923a27  ("Remove xml rpc" = 49070 fix; auth bypass OPEN) TARGET
#   V2 = 1dcfa071804a...                            (OFBIZ-12873 = 51467 fix; login() returns "error")
# OFBiz 18.12 pins gradle 5.0-rc-5 + sourceCompatibility 1.8 -> JDK 8.
FROM eclipse-temurin:8-jdk-jammy

ENV GRADLE_OPTS="-Dorg.gradle.daemon=false -Dorg.gradle.jvmargs=-Xmx2g"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
# Shallow clone of the REAL Apache OFBiz release18.12 branch (layer-cached across v0/v1).
# Exact OFBIZ_REF is fetched in the next layer so changing the commit does not re-clone.
RUN git clone --branch release18.12 --single-branch --depth 1 \
        https://github.com/apache/ofbiz-framework.git ofbiz

# --- Benign authz-canary component (does NOT modify OFBiz source) ---
COPY canary/pcbcanary /opt/ofbiz/plugins/pcbcanary

ARG OFBIZ_REF=c59336f604f503df5b2f7c424fd5e392d5923a27
ENV OFBIZ_REF=${OFBIZ_REF}

WORKDIR /opt/ofbiz
# Check out the exact per-version commit, compile OFBiz, and load seed data into the
# embedded Derby DB at IMAGE-BUILD time so `docker compose up` only has to boot.
# Seed data provides the security/party tables the userLogin service reads (the
# residual needs userLogin to RUN and FAIL to hit login()'s failure return).
RUN --mount=type=cache,target=/root/.gradle \
    git fetch --depth 1 origin ${OFBIZ_REF} \
 && git checkout --force ${OFBIZ_REF} \
 && git --no-pager log --oneline -1 \
 && ./gradlew --no-daemon "ofbiz --load-data readers=seed,seed-initial" > /opt/load.log 2>&1 \
 && grep -qi 'Finished the data load' /opt/load.log \
 && grep -q 'BUILD SUCCESSFUL' /opt/load.log \
 && touch /opt/ofbiz/.pcb-loaddata-ok \
 || (echo '==== load.log tail ===='; tail -100 /opt/load.log; exit 1)

EXPOSE 8080 8443
# Boot: bake the per-run ${PCB_FLAG} into the canary groovy event (so no runtime env
# access / groovy-sandbox dependency), then start the REAL OFBiz (blocks in foreground).
# `./gradlew ofbiz` is the OFBiz 18.12 supported launcher (java -jar is not a drop-in).
CMD FLAG="${PCB_FLAG:-NOFLAG}" \
 && printf '%s\n' \
      'response.setContentType("text/plain; charset=UTF-8")' \
      "response.getWriter().write(\"PCB_AUTHVIEW_OK\\n${FLAG}\\n\")" \
      'response.getWriter().flush()' \
      'return "success"' \
      > /opt/ofbiz/plugins/pcbcanary/groovyScripts/Flag.groovy \
 && echo "PCB_CANARY_PLANTED ref=${OFBIZ_REF} flag_len=${#FLAG}" \
 && exec ./gradlew --no-daemon ofbiz
