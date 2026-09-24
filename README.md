# Look Ahead Gateway BFF

Java 21 / Spring Boot Backend for Frontend (BFF) for the Angular application.
It owns browser sessions, server-held
OAuth tokens and fixed routing to Identity and the Learning Domain API. It has no database
connection or private signing key.

## Build and test one checkout

Install a Java 21 JDK, clone this repository, and run its pinned Gradle 9.6.1
Wrapper. No sibling checkout, private artifact registry or locally installed
project artifact is required. Dependencies come from Maven Central and the
Gradle Plugin Portal.

```sh
./gradlew --no-daemon clean test bootJar
```

Windows uses `gradlew.bat`. The executable is `build/libs/lookahead-gateway.jar`;
test reports are in `build/reports/tests/test/index.html`. The build retains Java
parameter names used by Spring MVC. Its Spring Boot BOM and plugin stay pinned
to the same version in `build.gradle`.

The application owns `ApiResponse` and `CsrfView`. These are small JSON transport
types, not a shared runtime JAR. Contract tests cover their serialization and
historical JSON inputs, byte-preserving Identity/Domain responses, error codes,
and credential filtering. Other services own their own transport types; changes
to an HTTP contract still require provider and consumer review.

The Wrapper checks the downloaded Gradle distribution against its published
SHA-256 checksum. CI additionally checks `gradle-wrapper.jar` against the
[official Gradle 9.6.1 checksum](https://downloads.gradle.org/distributions/gradle-9.6.1-wrapper.jar.sha256).
When upgrading Gradle, regenerate the Wrapper and update both reviewed checksums.

## Standalone local smoke run

Tests use synthetic data and temporary loopback servers; they do not require a
database, Identity, Domain API or private curriculum. You can also start the BFF
alone to inspect its readiness, CSRF response and anonymous access denial:

```sh
SPRING_PROFILES_ACTIVE=local \
LOOKAHEAD_ENVIRONMENT=local \
LOOKAHEAD_OAUTH_ISSUER=http://127.0.0.1:14350 \
LOOKAHEAD_FRONTEND_ORIGIN=http://127.0.0.1:14350 \
APP_OAUTH_CLIENT_ID=lookahead-smoke \
LOOKAHEAD_GATEWAY_CLIENT_SECRET=synthetic-smoke-only-not-a-real-secret \
LOOKAHEAD_IDENTITY_UPSTREAM=http://127.0.0.1:14351 \
LOOKAHEAD_DOMAIN_UPSTREAM=http://127.0.0.1:14352 \
LOOKAHEAD_GATEWAY_COOKIE_NAME=LOOKAHEAD_SMOKE_GATEWAY \
LOOKAHEAD_IDENTITY_COOKIE_NAME=LOOKAHEAD_SMOKE_IDENTITY \
PORT=14350 java -jar build/libs/lookahead-gateway.jar
```

Use a free loopback port; adjust the issuer and frontend origin together when
changing it. From a second terminal:

```sh
curl --fail http://127.0.0.1:14350/actuator/health/readiness
curl --fail http://127.0.0.1:14350/bff/api/v1/auth/csrf
curl --include http://127.0.0.1:14350/bff/api/v1/plans
```

Readiness returns `UP`, CSRF returns browser security-token metadata, and anonymous
plan access returns `401`. This checks the BFF process only. Login, curriculum and
saved plans require real Identity and Domain API instances with their databases
and matching environment configuration. The synthetic smoke credential is never
suitable for a deployed environment.

For a protected Author Delivery Plan visit, the browser keeps the exact
`/delivery-plan` destination through sign-in. Gateway accepts that path (and its
query or fragment) as an internal OAuth return destination, while rejecting
unrecognized `/delivery-plan/...` subpaths. The destination remains protected by
the Author capability check; this rule only preserves where a successful sign-in
returns.

## Container and CI

Build from this repository alone:

```sh
docker build --tag lookahead-gateway:local .
```

The Docker build runs all tests before packaging. The runtime image contains the
Java 21 JRE, `/opt/lookahead/app.jar` and the Java readiness helper in
`/opt/lookahead/health`. It runs as UID/GID `10001:10001`, listens on container
port `8080`, and checks `/actuator/health/readiness`. Its context allowlist
excludes repository history, local state, caches and private operational files.

GitHub Actions checks the Wrapper, runs the native Gradle tests and packaging,
then builds the image without pushing or deploying it. The workflow uses
read-only repository permissions and does not require AWS credentials. Infra
owns network, database and service orchestration; it consumes the built image.

## Runtime configuration

| Setting | Purpose |
| --- | --- |
| `LOOKAHEAD_ENVIRONMENT` | Explicit `local`, `dev` or `prod` |
| `SPRING_PROFILES_ACTIVE` | Matching environment profile; the entry point adds `gateway` |
| `LOOKAHEAD_OAUTH_ISSUER`, `LOOKAHEAD_FRONTEND_ORIGIN` | Same public browser origin |
| `APP_OAUTH_CLIENT_ID` | Dedicated client registered with Identity |
| `LOOKAHEAD_GATEWAY_CLIENT_SECRET` | Client secret shared only with Identity |
| `LOOKAHEAD_IDENTITY_UPSTREAM` | Fixed Identity origin |
| `LOOKAHEAD_DOMAIN_UPSTREAM` | Fixed Domain API origin |
| `LOOKAHEAD_SECRETS_DIRECTORY` | Optional config-tree directory, defaults to `/run/secrets/` |
| `LOOKAHEAD_GATEWAY_COOKIE_NAME`, `LOOKAHEAD_IDENTITY_COOKIE_NAME` | Distinct environment-specific session-cookie names |
| `LOOKAHEAD_BIND_ADDRESS`, `PORT` | Defaults to loopback and `8080`; image binds inside its container |

Configuration-tree files can supply the named secret properties instead of
environment variables. Never commit real client secrets. DEV/PROD enforce HTTPS
origins and secure cookies; local mode permits fixed loopback/service HTTP
origins. Local host ports must bind to loopback. Cookie names must differ between
Gateway and Identity and between side-by-side deployments on the same hostname.

Optional local author previews use `APP_AUTHOR_PREVIEWS_ENABLED`,
`APP_AUTHOR_PREVIEWS_UPSTREAM` and the separate server-side shared key described
by `AuthorPreviewSettings`. They stay disabled by default.

The repository remains
[lookahead-learning-gateway-bff](https://github.com/lookahead99ms/lookahead-learning-gateway-bff).
The `gateway` runtime role, Java entry point, configuration names and executable
name remain unchanged. Building a new image does not replace a running service.

## Logical sign-in controls

Identity owns durable sign-in admission and selective revocation. The Gateway exposes
[seven exact account/challenge routes](docs/sign-in-api.md), retains Identity CSRF,
and checks private BFF requests against the Identity-backed Domain account endpoint.
Verification outages fail closed; revoked sessions cannot use BFF CSRF or author
preview access just because a local OAuth principal remains in memory.

Set `LOOKAHEAD_SIGNIN_BINDING_COOKIE_NAME` and
`LOOKAHEAD_SIGNIN_CHALLENGE_COOKIE_NAME` consistently with Identity. Defaults are
`LOOKAHEAD_SIGNIN_BINDING` and `LOOKAHEAD_SIGNIN_CHALLENGE`. All three Identity cookie
names and the Gateway cookie name must differ; use deployment-specific names for
side-by-side LOCAL environments. These cookies remain server controlled and never
expose OAuth tokens to the frontend. No Google provider is activated by this work.
## Author preview review decisions

The authenticated BFF exposes three narrowly allowed Domain review routes for
listing governed artifacts, reading their event history and recording a decision.
See [Author review proxy](docs/author-review-api.md) for paths, request fields,
CSRF, idempotency and proxy limits. Domain independently requires the author
capability and records append-only review history. Recording a decision does not
edit delivery tickets, Git or GitHub. No new BFF configuration is required.
