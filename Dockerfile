FROM eclipse-temurin:25-jdk@sha256:97014c4b396021f9ddb7d592a7dbedb0c4e4215c29e03dc01c393558aefb71c2 AS build
WORKDIR /workspace
ENV GRADLE_USER_HOME=/tmp/gradle-cache
COPY gradlew build.gradle settings.gradle ./
COPY gradle/wrapper/ gradle/wrapper/
COPY src/ src/
COPY tools/container/Healthcheck.java tools/container/Healthcheck.java
RUN ./gradlew --no-daemon clean test bootJar \
    && mkdir /workspace/health \
    && javac --release 21 -d /workspace/health tools/container/Healthcheck.java

FROM eclipse-temurin:25-jre@sha256:bb036ed6cfdc57e3da7c22634d15f1b840d2caf76183861c80e81ca4b5104abb AS runtime
WORKDIR /opt/lookahead
RUN groupadd --gid 10001 lookahead && useradd --uid 10001 --gid 10001 --no-create-home lookahead
COPY --from=build --chown=10001:10001 /workspace/build/libs/lookahead-gateway.jar /opt/lookahead/app.jar
COPY --from=build --chown=10001:10001 /workspace/health /opt/lookahead/health
USER 10001:10001
ENV LOOKAHEAD_BIND_ADDRESS=0.0.0.0 PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 CMD ["java", "-cp", "/opt/lookahead/health", "Healthcheck"]
ENTRYPOINT ["java", "-jar", "/opt/lookahead/app.jar"]
