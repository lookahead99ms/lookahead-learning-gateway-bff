# Gateway application

Java 21 / Spring Boot browser-facing BFF. It owns browser sessions, server-held
OAuth tokens and fixed routing to Identity and Platform. It has no database
connection or private signing key.

Keep `lookahead-learning-backend`, `lookahead-learning-identity` and
`lookahead-learning-platform` alongside this directory. From the shared build:

```sh
cd ../lookahead-learning-backend
./mvnw -pl :gateway-app -am verify
```

The executable is `../lookahead-learning-gateway/target/lookahead-gateway.jar`.
See the [backend build and environment contract](../lookahead-learning-backend/README.md)
for required settings and image commands. Infrastructure owns local service
orchestration. Building this candidate does not change the existing running API.
