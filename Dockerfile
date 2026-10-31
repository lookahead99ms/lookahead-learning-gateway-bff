FROM eclipse-temurin:24-jdk-noble@sha256:dacac8e9a0df0d2bd24e702b4431132875c249930b70555ebd7ca285b5bee684 AS build
ARG RELEASE_VERSION=dev
ARG BUILD_VERSION=0.0.1-SNAPSHOT
ARG SOURCE_REVISION=local
WORKDIR /workspace
ENV GRADLE_USER_HOME=/tmp/gradle-cache
COPY gradlew ./
COPY gradle/wrapper/ gradle/wrapper/
RUN ./gradlew --no-daemon --version
COPY build.gradle settings.gradle ./
COPY src/ src/
# DLV-914: the jar is lookahead-gateway-<version>.jar and /actuator/info reports version, release tag and commit.
RUN ./gradlew --no-daemon "-PreleaseVersion=$BUILD_VERSION" "-PreleaseTag=$RELEASE_VERSION" "-PsourceRevision=$SOURCE_REVISION" clean test bootJar \
    && test -f "/workspace/build/libs/lookahead-gateway-$BUILD_VERSION.jar" \
    && mkdir /workspace/health \
    && javac --release 21 -d /workspace/health src/main/java/com/lookahead/gateway/health/ContainerHealthcheck.java

FROM eclipse-temurin:24-jre-noble@sha256:b416d02335e702b0403ff280de9475a3348e29382285969c9d4e17862ce632e7 AS runtime
ARG RELEASE_VERSION=dev
ARG BUILD_VERSION=0.0.1-SNAPSHOT
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      com.lookahead.app="gateway-bff"
WORKDIR /opt/lookahead
RUN groupadd --gid 10001 lookahead && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin lookahead \
    && chown 10001:10001 /tmp && chmod 1777 /tmp
COPY --from=build --chown=10001:10001 /workspace/build/libs/lookahead-gateway-${BUILD_VERSION}.jar /opt/lookahead/app.jar
COPY --from=build --chown=10001:10001 /workspace/health /opt/lookahead/health
COPY deployment/container/dns.security /opt/lookahead/dns.security
# ECS copies a VOLUME path's ownership into the task's empty bind mount; without it the Fargate
# mount at /tmp is root-owned 0755 and Tomcat (UID 10001) cannot create its tempDir (DLV-968). /tmp keeps the
# conventional sticky 1777 mode: Docker gives an unparameterised tmpfs the directory's mode, so local stacks that
# mount `/tmp:rw,noexec,nosuid,size=…` stay writable; only the ownership is new.
VOLUME ["/tmp"]
USER 10001:10001
ENV LOOKAHEAD_BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 CMD ["java", "-cp", "/opt/lookahead/health", "com.lookahead.gateway.health.ContainerHealthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/lookahead/app.jar"]
