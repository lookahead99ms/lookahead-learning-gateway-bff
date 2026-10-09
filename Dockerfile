FROM eclipse-temurin:21-jdk@sha256:92a2a4d7a928d057e7bd999c418d66c26a34eb9a0442f3ab67721c3f88110b2d AS build
WORKDIR /workspace
ENV GRADLE_USER_HOME=/tmp/gradle-cache
COPY gradlew ./
COPY gradle/wrapper/ gradle/wrapper/
RUN ./gradlew --no-daemon --version
COPY build.gradle settings.gradle ./
COPY src/ src/
RUN ./gradlew --no-daemon clean test bootJar \
    && mkdir /workspace/health \
    && javac --release 21 -d /workspace/health src/main/java/com/lookahead/gateway/health/ContainerHealthcheck.java

FROM eclipse-temurin:21-jre@sha256:cff19e6215689161eb6162c11b86b0c60ddf802164f2eaf48d570f8fb79a36c5 AS runtime
WORKDIR /opt/lookahead
RUN groupadd --gid 10001 lookahead && useradd --uid 10001 --gid 10001 --no-create-home lookahead
COPY --from=build --chown=10001:10001 /workspace/build/libs/lookahead-gateway.jar /opt/lookahead/app.jar
COPY --from=build --chown=10001:10001 /workspace/health /opt/lookahead/health
USER 10001:10001
ENV LOOKAHEAD_BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 CMD ["java", "-cp", "/opt/lookahead/health", "com.lookahead.gateway.health.ContainerHealthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/lookahead/app.jar"]
