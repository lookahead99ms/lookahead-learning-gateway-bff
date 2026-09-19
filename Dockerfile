FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace
ENV GRADLE_USER_HOME=/tmp/gradle-cache
COPY gradlew build.gradle settings.gradle ./
COPY gradle/wrapper/ gradle/wrapper/
COPY src/ src/
COPY tools/container/Healthcheck.java tools/container/Healthcheck.java
RUN ./gradlew --no-daemon clean test bootJar \
    && mkdir /workspace/health \
    && javac --release 21 -d /workspace/health tools/container/Healthcheck.java

FROM eclipse-temurin:21-jre AS runtime
WORKDIR /opt/lookahead
RUN groupadd --gid 10001 lookahead && useradd --uid 10001 --gid 10001 --no-create-home lookahead
COPY --from=build --chown=10001:10001 /workspace/build/libs/lookahead-gateway.jar /opt/lookahead/app.jar
COPY --from=build --chown=10001:10001 /workspace/health /opt/lookahead/health
USER 10001:10001
ENV LOOKAHEAD_BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 CMD ["java", "-cp", "/opt/lookahead/health", "Healthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/lookahead/app.jar"]
