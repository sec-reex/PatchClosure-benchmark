# Faithful sink image for the OWASP Java HTML Sanitizer STYLE/noscript incomplete-fix pair.
# The ONLY thing that varies across v0/v1/v2 is the pinned sanitizer version (build-arg SANITIZER_VER
# -> maven property sanitizer.version):
#   v0 = 20200713.1 (pre-CVE-2021-42575: HtmlStreamRenderer appends <style> CDATA content UNGUARDED
#                    -> svg>style foreign-content desync leaks a live <script>)
#   v1 = 20211018.1 (CVE-2021-42575 fix = TARGET, incomplete: commit be33ec6 "Render style tag
#                    content more strictly" wraps <style> text in /*<![CDATA[<!--*/ ... /*-->]]>*/
#                    and drops content containing <![CDATA[ / ]]> / <!-- / --> . That neutralizes the
#                    svg>style desync but the SAME wrapper fails inside <noscript> -> residual)
#   v2 = 20260101.1 (CVE-2025-66021 fix = COMPLETE: commit 4149cf0 detects & strips tag-like content
#                    such as <script> / </noscript> from allowTextIn("style") text)
#
# Only the sanitizer jar differs; guava + the servlet-free JDK HttpServer host are constant. The
# maven build resolves the pinned sanitizer + its guava transitive dep and shades a runnable jar.
ARG MAVEN_TAG=3.9-eclipse-temurin-11
FROM maven:${MAVEN_TAG}
ARG SANITIZER_VER=20211018.1
WORKDIR /app
COPY maven-settings.xml /root/.m2/settings.xml
COPY pom.xml /app/pom.xml
COPY src /app/src
# Whole published Central jar + guava. Retry: gpu1 compose flakes on a single wagon GET.
RUN set -eux; \
    i=1; \
    while [ "$i" -le 5 ]; do \
      mvn -B -s /root/.m2/settings.xml \
        -Dsanitizer.version="${SANITIZER_VER}" \
        -Dmaven.wagon.http.retryHandler.count=5 \
        -Dmaven.wagon.http.retryHandler.requestSentEnabled=true \
        -Dmaven.wagon.httpconnectionManager.ttlSeconds=120 \
        clean package && break; \
      echo "mvn Central retry ${i}" >&2; \
      i=$((i + 1)); \
      sleep 8; \
    done; \
    test -f /app/target/app.jar
EXPOSE 80
CMD ["java", "-jar", "/app/target/app.jar"]
