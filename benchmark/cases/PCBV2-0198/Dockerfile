# Faithful-core image for Spring's UriComponentsBuilder host-validation bypass
# (CVE-2024-22243 -> CVE-2024-22259). Runs the SAME tiny app against a per-version spring-web JAR.
# The app depends ONLY on spring-web:${SPRING_VER}; the parser is the real Spring class, not a copy.
FROM maven:3.9-eclipse-temurin-17
ARG SPRING_VER=5.3.32
ENV SPRING_VER=${SPRING_VER}
WORKDIR /app
COPY pom.xml /app/pom.xml
# Resolve spring-web:${SPRING_VER} + transitive deps into /app/libs (cached per version).
RUN mvn -q -B dependency:copy-dependencies \
        -Dspring.version=${SPRING_VER} \
        -DoutputDirectory=/app/libs -DincludeScope=runtime
COPY Harness.java /app/Harness.java
RUN javac -cp "/app/libs/*" -d /app/out /app/Harness.java
EXPOSE 8080
CMD ["sh", "-c", "java -cp /app/out:/app/libs/* Harness"]
