# Look Ahead Gateway BFF

Java 21 / Spring Boot Backend for Frontend (BFF) for the Angular application.
It owns browser sessions, server-held
OAuth tokens and fixed routing to Identity and the Learning Domain API. It has no database
connection or private signing key.

Keep `lookahead-learning-toolkit`, `lookahead-learning-identity` and
`lookahead-learning-domain-api` alongside this directory. From the shared build:

```sh
cd ../lookahead-learning-toolkit
./mvnw -pl :gateway-app -am verify
```

The local folder and GitHub repository are named `lookahead-learning-gateway-bff`:
[lookahead99ms/lookahead-learning-gateway-bff](https://github.com/lookahead99ms/lookahead-learning-gateway-bff).
The existing
`gateway` runtime role, `gateway-app` Maven artifact and `lookahead-gateway.jar`
executable name remain compatible with the local service configuration.

The executable is `../lookahead-learning-gateway-bff/target/lookahead-gateway.jar`.
See the [backend build and environment contract](../lookahead-learning-toolkit/README.md)
for required settings and image commands. Infrastructure owns local service
orchestration. Building this candidate does not change the existing running API.
