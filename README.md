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
| `LOOKAHEAD_DOMAIN_TRANSPORT` | `https` default, or explicit cloud-only `service-connect-tls` with exact `http://domain:8080` alias |
| `LOOKAHEAD_SECRETS_DIRECTORY` | Optional config-tree directory, defaults to `/run/secrets/` |
| `LOOKAHEAD_GATEWAY_COOKIE_NAME`, `LOOKAHEAD_IDENTITY_COOKIE_NAME` | Distinct environment-specific session-cookie names |
| `LOOKAHEAD_BIND_ADDRESS`, `PORT` | Defaults to loopback and `8080`; image binds inside its container |

Configuration-tree files can supply the named secret properties instead of
environment variables. Never commit real client secrets. DEV/PROD enforce HTTPS
origins and secure cookies, with only the explicit Service Connect Domain alias
exception described below; local mode permits fixed loopback/service HTTP
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

In Local, Identity owns durable sign-in admission and selective revocation. The Gateway exposes
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


## AWS DEV deployment candidate (DLV-810)

`deployment/service.yaml` is the application-owned service contract for the local AWS candidate. It declares health, capacity, immutable image/release inputs and symbolic approved resource/secret references. Shared DEV/PROD values, IAM, S3, networking, CloudFormation and tooling belong to Infra. YAML uses JSON syntax. Current image/evidence values are unresolved and desired count is zero; this is not an activated cloud profile. Local configuration and authorization are preserved. See the sibling Infra `aws/devprod/README.md` for local planning commands and remaining application/identity/bootstrap gates. No resource creation, upload or GitHub activation has been performed.

Deployment direction: this application owns its service YAML and future thin caller to an immutable-pinned Infra reusable workflow. The v2 manifest separates shared settings from DEV/PROD overrides. Infra owns bootstrap/IAM/security groups/templates/orchestration; see workspace Infra `docs/deployment/README.md`. Build-once digest promotion, required scans and separate DEV/PROD approvals remain gates, not enabled deployment behavior.

## Service deployment configuration

`deployment/service.yaml` uses `lookahead-service/v2`: `shared` owns service port, health, settings and approved resource/secret/Infra output references; `environments.dev` and `.prod` select capacity, image digest, content release and activation evidence. Both candidates retain zero tasks. Shared account/region values and all infrastructure remain Infra-owned. Infra's maintained `aws/devprod/parameter-bindings.yaml` validates every template parameter; `scripts/aws_deployment.py plan --environment dev|prod` generates an offline plan. See Infra `docs/deployment/README.md` for commands and activation gates. No application contract or Local Docker behavior changed; AWS deployment remains blocked.

October8 candidate service configuration adds explicit Fargate runtime/private networking, ingress/target-group references, optional alarm references, and per-environment scaling min/max, CPU targets, cooldowns and alarm thresholds. Desired/min tasks stay0 and scaling/alarms disabled. Fargate uses CPU/memory, not an EC2 instance type. Infra owns conditional scaling/IAM/CloudWatch resources; see Infra docs/deployment/README.md.

Deployment `service.yaml` now declares task startup, health probes, temporary disk, logging/rollout settings and approved environment/Secrets Manager bindings. Java DEV/PROD sections declare Xms128 MiB / Xmx512 MiB and approved JVM args for provisional 1 GiB tasks, leaving explicit native/probe budget; load testing remains required. Infra shared values and maintained templates remain authoritative; see Infra `docs/deployment/README.md` → JVM and task configuration. Local Docker/runtime behavior is unchanged and AWS activation remains blocked.

AWS candidate `deployment/service.yaml` now references the shared application task role and separate shared Fargate execution role from its owning environment foundation. Active cloud applications reuse this pair; DEV/PROD have separate role resources/scopes. Infra owns policies, trust and validation; service-specific secret mappings and existing authorization are preserved. See Infra `docs/deployment/README.md` → Two shared IAM roles per environment. No cloud activation.


## DEV/PROD Cognito and Domain sign-in ownership

Set `LOOKAHEAD_ENVIRONMENT` explicitly to `dev` or `prod` to select Cognito. Local
continues using its existing Identity endpoints and cookie/CSRF contract. Cloud
requires `LOOKAHEAD_COGNITO_ISSUER`, `LOOKAHEAD_COGNITO_MANAGED_LOGIN`,
`LOOKAHEAD_COGNITO_SCOPE_PREFIX`, `APP_OAUTH_CLIENT_ID`, the ECS-injected
`LOOKAHEAD_GATEWAY_CLIENT_SECRET` and `LOOKAHEAD_DOMAIN_GATEWAY_SECRET`, plus fixed
HTTPS frontend and Domain origins by default. The selected AWS Service Connect
mode below constrains the Domain application hop to its exact proxy alias.
The issuer and managed-login hostname must
share the configured AWS region. Cloud does not create an Identity proxy.

The Gateway uses OIDC authorization code + PKCE, state and nonce, with fresh
managed authentication. Tokens, the Domain binding proof and replacement
challenge remain in the server session. Domain owns durable admission, the
cloud two-sign-in limit and revocation. Gateway owns browser sessions and CSRF.
Cloud account mutation routes use Gateway session-bound CSRF, including the
replacement challenge. Ordinary application requests cannot use a pending
challenge; loading the UI or CSRF does not destroy that challenge.

Successful replacement resumes through `/bff/login` only after Domain confirms
admission, preserving a safe return destination. Recent-auth confirmation uses
`/bff/login?reauthenticate=true&returnTo=%2Faccount`. Password-change acknowledgement
or current-sign-in revocation invalidates the Gateway session. Logout confirms
Domain revocation before clearing browser state; provider revoke uncertainty is
reported separately. The browser receives only a same-origin logout bridge,
which redirects to the configured Cognito logout endpoint.

No AWS SDK client or credentials are needed in Gateway or Angular: these are
OIDC/HTTP calls. Deployment, live Cognito connectivity and failover remain
unverified. Session loss requires a fresh login; this candidate does not claim
seamless Gateway failover. See [sign-in API modes](docs/sign-in-api.md).

### Private Domain transport

`LOOKAHEAD_DOMAIN_TRANSPORT` defaults to `https`; DEV/PROD then require a fixed
HTTPS `LOOKAHEAD_DOMAIN_UPSTREAM`. The selected AWS candidate instead sets
`LOOKAHEAD_DOMAIN_TRANSPORT=service-connect-tls` together with the exact
`LOOKAHEAD_DOMAIN_UPSTREAM=http://domain:8080`. This HTTP address is the ECS
Service Connect client alias: the application communicates with its local proxy,
and Service Connect owns TLS encryption between tasks. No other plaintext host,
port, path, user information, query or fragment is accepted. Local cannot select
this cloud mode and retains its existing service/loopback HTTP configuration.

Infra must enforce the proxy routing, TLS certificate/rotation lifecycle and
security groups that prevent direct plaintext task ingress. Gateway's setting
alone does not prove those controls are deployed. Cognito issuer, token, userinfo
and JWKS endpoints remain HTTPS with the standard JDK trust configuration. Domain
and provider HTTP clients retain bounded timeouts and do not follow redirects;
tokens, binding proofs and internal-service secrets remain server-side.

Tests run the browser security contract for both DEV and PROD with each supported
Domain transport and reject malformed proxy aliases. They verify the application
contract with controlled responses; actual Service Connect encryption, proxy
health, certificate rotation and blocked direct ingress require AWS evidence.

Run `./gradlew test bootJar` for the Local regressions and controlled-HTTP cloud
security tests. Fixtures cover CSRF, restricted challenges, replacement retry,
return destinations, password-session invalidation and logout failure behavior;
they do not contact AWS or certify a deployed environment.

## Environment tests and coverage

Run `./gradlew check bootJar` for the complete Gateway test suite, executable JAR,
JaCoCo HTML/XML reports and the minimum **85% production line coverage** gate.
The gate measures every production class without project-level exclusions.
Branch coverage is reported separately. Reports are generated under
`build/reports/jacoco/test/`; running filtered tests produces a partial report,
so use the complete `check` command for delivery evidence. The existing CI build
step also invokes `check` so its local workflow definition enforces this gate.

| Boundary | Automated coverage |
| --- | --- |
| Local | Actual Identity proxy/security filters, session/CSRF forwarding, account routes, safe redirects and environment YAML bindings |
| DEV | Actual Gateway security filters with controlled Domain/provider responses: admission, restricted challenge, CSRF, logout, password-session invalidation and safe continuation |
| PROD | The same cloud security contract under separate PROD origins, client, scopes and AWS region; confirms Local proxy/controller beans are absent |
| Environment wiring | Actual `application.yml` placeholders, provider URLs, redirect URI, secrets, secure cookies, HTTPS default, exact Service Connect alias and rejected cross-region/transport settings |
| ID token validation | Generated RSA signatures and loopback JWKS with configured DEV/PROD issuer/client validation; rejects wrong signature, issuer, audience and expired tokens |

Provider fixtures and generated keys are synthetic. These checks do not certify
live Cognito login/token exchange, external TLS certificates, private network
reachability, ECS secret delivery, deployed cookie/proxy behavior or multi-instance
recovery. Those remain deployment integration checks. The Gateway owns no RDS
connection; database connectivity and schema/readiness tests belong to Domain.

The container readiness probe is production Java source at `src/main/java/com/lookahead/gateway/health/ContainerHealthcheck.java`, so the ordinary JaCoCo report includes it. Tests use loopback HTTP fixtures to cover healthy and failed responses, malformed bodies, redirects, unavailable endpoints, timeouts and interruption. The container still probes only `127.0.0.1:8080/actuator/health/readiness`, with a two-second connection limit and three-second request limit. The process-exit wrapper remains in the measured source inventory.

Docker resolves the checksum-pinned Gradle wrapper in a source-independent layer before copying build declarations and application sources. This reuses the wrapper download when source files change; dependency versions and the `clean test bootJar` build remain unchanged.

DEV/PROD client and Gateway-to-Domain secrets must contain the injected secret values. Startup rejects secret ARNs, unresolved configuration/CloudFormation references, whitespace/control characters and invalid lengths; ECS task-definition `valueFrom` resolves the ARN before application startup. Local configuration retains its existing contract.

## SAST gate diagnostics

`python3 tools/security/check.py sarif` requires completed CodeQL invocations,
valid rule/result inventories and exercised, source-bound exceptions. A failure
prints a reviewed constant reason (for example, missing invocation inventory or
unexercised exception) while leaving untrusted error text and SARIF messages out
of public logs. Warning/error notifications still block; this diagnostic change
does not waive findings or weaken the security gate. Raw SARIF and source
databases remain unpublished. Run the tooling regressions with
`python3 -m unittest discover -s tools/security -p 'test_*.py'`.

SAST exception hashes are also checked in the first tooling-test step; review
the security boundary before updating a hash after a source change. Expiry and
mandatory exception usage stay enforced. SARIF trace notifications (`none`)
are informational alongside `note`; warnings, errors and unknown levels block.
A rejected notification logs only its level and a bounded Java diagnostic ID,
never its message, source snippet, locations or properties.


The Docker builder uses digest-pinned Eclipse Temurin Java 21 Ubuntu 24.04
(`21-jdk-noble`); the runtime uses a separately pinned Java 21 Alpine image
(`21-jre-alpine`). The runtime uses musl libc and Alpine's account-creation
commands, retains numeric user/group 10001 and the existing Java health probe,
and needs no added curl or application SDK. Distroless Java 21 Debian candidates
were investigated but rejected because their complete package scans still found
blocking vulnerabilities. No image exception is used.

The scanner blocks High, Critical and Unknown severities, including unfixed
findings, and requires complete OS/Java package coverage for built images.
A passing base scan does not certify the application: CI scans both exact pinned
bases and the final image. Local Docker smoke checks are separate from AWS
activation, network, IAM and cloud profile verification.



The reviewed `java/user-controlled-bypass` login finding is source-bound to
`GatewayController.java` and expires on 2026-10-19. The request's reauthenticate
parameter can force fresh OAuth; it cannot grant access. Reusing a sign-in needs
an authenticated server session, its stored client and successful Domain
verification. `CloudGatewaySecurityIntegrationTest` covers missing clients,
anonymous callers, rejected Domain verification and forced reauthentication;
existing CSRF and restricted-session regressions remain active. Any controller
source change or expiry requires a new review; other findings remain blocking.

On October 9, 2026, the pinned AMD64 candidates passed complete base/final
package scans and the isolated three-application Local authentication contract
with fresh synthetic PostgreSQL databases. All applications ran as 10001:10001
with a read-only root filesystem, capped temporary storage and healthy Java
readiness probes. This does not certify Cognito or RDS connectivity in AWS.
