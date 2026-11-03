# Logical sign-in API source notes

DLV-920 Gateway mappings below are exact, with no wildcard forwarding. In Local, Identity owns authentication, account ownership, CSRF and durable admission/revocation. Requests use Identity CSRF obtained from `/api/v1/auth/csrf`, including the restricted challenge flow; the BFF CSRF token is different.

| Method | Path | JSON request |
| --- | --- | --- |
| GET | `/api/v1/account/sign-ins` | None |
| POST | `/api/v1/account/sign-ins/revoke` | `{ "signInId": "opaque-reference" }` |
| POST | `/api/v1/account/sign-ins/revoke-others` | `{}` |
| POST | `/api/v1/account/sign-ins/label` | `{ "label": "My browser" }` |
| GET | `/api/v1/auth/sign-in-challenge` | None |
| POST | `/api/v1/auth/sign-in-challenge/replace` | `{ "signInId": "opaque-reference" }` |
| POST | `/api/v1/auth/sign-in-challenge/cancel` | `{}` |

Identity response envelopes/errors pass through unchanged. HTTP 409 `SIGN_IN_LIMIT` is a restricted replacement challenge, not a completed login. Gateway does not turn that response into authenticated BFF access. Account/challenge payloads are bounded to 8192 bytes in both directions. Unsupported methods do not reach Identity. No bearer token is forwarded from browser headers to these routes.

A successful response with `data.reauthenticationRequired: true` clears the local BFF session and expires its configured cookie. Other successful responses preserve that session. Identity errors preserve their code/status; upstream infrastructure failures are sanitized to 503. All responses are no-store.

Every authenticated private BFF API request (including CSRF retrieval) and author preview is verified through fixed Domain `/api/v1/auth/me` with the server-owned managed access token. Domain's Identity-backed token validation is authoritative; no positive result is cached. A rejected/revoked token or invalid refresh grant clears the BFF session; verification outages deny access with 503 while preserving local state. Public content and logout remain reachable through their existing rules. This adds one verification round trip per private BFF request and does not make in-flight requests transactional with a simultaneous revoke.

The Identity session, binding and challenge cookies are the only browser cookies relayed to Identity or accepted back from it. Configure all three separately from the Gateway cookie and from other deployments on the same hostname. A binding cookie is not a hardware identifier; a challenge cookie is not a full authenticated session. No cookie value or OAuth token is returned as API JSON.

Gateway's `/bff/login?returnTo=` redirect allowlist includes the exact protected
`/delivery-plan` path, with a safe query or fragment. The browser's local
return-path check uses the same destination. Unrecognized Delivery Plan subpaths
fall back to `/`; the page and its private data still require the Author grant.

These are Gateway source notes for the private generated API reference. Identity defines the authoritative inventory/challenge response schemas and error catalogue. Full cross-service admission/concurrency verification remains a release gate owned by the parent DLV-920 work; Gateway unit/transport tests alone do not prove it.


## Cloud mode (`dev` / `prod`)

The seven browser routes above remain stable. Cognito authenticates the user;
Domain owns `(issuer, subject)` account mapping, durable admission and revocation;
Gateway holds OAuth tokens, proof/challenge secrets and session CSRF. The Local
Identity controller and proxy security chain are inactive. Cloud additionally
serves GET/POST `/api/v1/account/profile`, POST `/api/v1/account/password`, and
`/api/v1/auth/options` with `managedLogin: true`.

`/api/v1/auth/csrf` and `/bff/api/v1/auth/csrf` use the same Gateway session token.
All cloud mutations require it. Browser authorization, proof, challenge and
internal-service secret headers are never forwarded. Gateway generates a random
proof and sends it with its provider access token to Domain. Only the exact
internal account action paths receive the injected Gateway service secret.
Domain responses are capped at 16 KiB and infrastructure errors are sanitized.

An OAuth callback first requests Domain admission. A pending replacement result
redirects to `/sign-in/choose?returnTo=...`, preserving a sanitized destination.
It can retrieve CSRF and read/replace/cancel the restricted challenge, but cannot
access ordinary accounts, BFF data, author previews or content. Rejected ordinary
requests preserve the challenge so UI bootstrap cannot erase the pending choice.
Successful replacement keeps its server-side challenge for an idempotent retry
until `/bff/login` confirms Domain `/api/v1/auth/me` and clears the challenge.
No extra Cognito login is required for that admitted continuation.

Every admitted private BFF request still checks Domain; no positive validity is
cached. Fresh authentication requires the managed sign-in redirect and explicit
resubmission of the intended change. Successful password change/current-session
revocation clears OAuth credentials and invalidates the Gateway session. An
unconfirmed password response preserves the browser session for recovery; Domain
remains authoritative about whether credentials or durable admission changed.

Logout first asks Domain to revoke durable admission. Failure returns 503 without
claiming logout. Once Domain confirms denial, Gateway attempts provider refresh
token revocation and clears local OAuth/session state even if that provider call
fails. The response reports `providerRevocationConfirmed` separately and returns
`/bff/logout/complete` on the configured frontend origin. The bridge redirects to
Cognito managed logout with fixed client ID and fixed `/sign-in` return URI; tokens
are never embedded in a browser URL.

These paths are locally verified with controlled HTTP fixtures and the actual
Spring Security filter chain. AWS endpoint behavior, deployment topology and
cross-instance recovery remain separate release gates.

Cloud Domain transport defaults to HTTPS. The explicit deployment setting
`LOOKAHEAD_DOMAIN_TRANSPORT=service-connect-tls` permits only
`LOOKAHEAD_DOMAIN_UPSTREAM=http://domain:8080`, the selected ECS Service Connect
client alias. The application-to-proxy hop is HTTP; Infra owns TLS between tasks
and prevents direct plaintext ingress. This setting changes no browser API or
authorization contract. Provider endpoints retain HTTPS and standard trust;
requests never follow redirects. Local keeps its existing transport configuration.
Controlled-response tests do not establish deployed proxy encryption or certificate
rotation; those remain release evidence requirements.

## Lower-cost DEV admission routes (`lower-cost-dev` profile)

These Gateway-owned routes exist only when the DEV admission profile is active; they are not
part of Local or PROD. Every other route requires an admitted session first.

Since DLV-969 (November 2, 2026) the gate accepts a sign-in to the Look Ahead pool and nothing
else. The gate page is our own sign-in page: **Continue with Google** (only while
`app.cognito.google-sign-in` / `LOOKAHEAD_GOOGLE_SIGN_IN` is true) links to
`/bff/login?provider=google&returnTo=/`, and **Sign in with email and password** links to
`/bff/login?provider=password&returnTo=/`. When the callback succeeds with a fresh `auth_time` (at
most 120 s old, at most 30 s ahead) the Gateway records the gate admission for its 8-hour absolute
window and asks Domain to admit the account. **The gate stays open only if Domain admits it**
(README decision 2: nothing beyond the landing page without the owner's approval):

- `403 ACCOUNT_ADMISSION_REQUIRED` (a new or still-waiting account) ends the learner sign-in, drops
  every gate admission on the session, including one left by an earlier sign-in in the same
  browser, and redirects to `/dev/access?access=pending`.
- Any other refusal ends the learner sign-in and puts back the gate the browser held before. With an
  open gate it lands on `/sign-in?error=admission`; without one, on `/dev/access?error=signin`.
- A failed provider sign-in (`loginFailed`) lands on `/dev/access?error=signin` outside an open
  gate and on `/sign-in?error=oauth` inside one.

The tester pool, its client registration, its `AdminGetUser` directory check and the 5-minute
re-check are no longer consulted or present in the code. Without the gate (PROD) a waiting account
lands on `/?access=pending`.

### Choosing the provider (DLV-969)

`/bff/login` takes an optional `provider`: `google` or `password`; any other value is ignored. It
travels to `/oauth2/authorization/lookahead?provider=…`, where the authorization request gains:

| Provider | `identity_provider` | `prompt` | Why |
| --- | --- | --- | --- |
| none | not sent | `login` | Cognito's managed login page, as before |
| `password` | `COGNITO` | `login` | Cognito's password form only |
| `google` (switch on) | `Google` | `select_account` | Cognito goes straight to Google; Google rejects `prompt=login`, and the chooser lets someone switch accounts after signing out |

`google` with the switch off falls back to the first row. `GET /api/v1/auth/options` reports the
switch as `google`.

| Method | Path | Response |
| --- | --- | --- |
| GET | `/dev/access` | `200 text/html` access page (our sign-in page) whose buttons link to `/bff/login?provider=google&returnTo=%2F` (switch on) and `/bff/login?provider=password&returnTo=%2F`; `?access=pending` and `?error=…` add one fixed notice, never request text; `Content-Security-Policy: default-src 'none'` plus the hash of its one style block |
| GET | `/bff/login`, `/oauth2/authorization/lookahead`, `/login/oauth2/code/lookahead` | pass the gate unadmitted so the learner sign-in can run; the callback's success handler grants the gate (`ADMISSION_GRANTED`) or, for a stale `auth_time`, ends the sign-in (`ADMISSION_DENIED`, `302 /dev/access?error=signin` without an earlier open gate) |
| GET | `/dev/csrf` | `200 {"headerName":"X-CSRF-TOKEN","token":...}` (no admission required) |
| GET | `/dev/session` | admitted: `200 {"dev":true,"deadline":"" or ISO instant,"warning":bool,"maintenance":bool}`; operations table unavailable: `503 {"code":"DEV_STATUS_UNAVAILABLE"}`; not admitted or expired: `401 {"code":"DEV_ADMISSION_REQUIRED"}` (October 30, 2026: previously a `302` redirect to `/dev/access`; the `503 DEV_ADMISSION_UNAVAILABLE` answer left with the directory check) |
| POST | `/dev/leave` | requires `X-CSRF-TOKEN`; `200 {"logoutUrl","learnerSignOutConfirmed","providerRevocationConfirmed":"false"}`; missing token `403` |
| GET | `/dev/leave/complete` | `302 /dev/access` (the learner provider is the gate's provider, so there is no second logout) |

Before admission, browser navigation routes answer `302 /dev/access`; `/api/`, `/bff/`, `/content/`,
`/dev/` and non-GET requests answer `401 {"code":"DEV_ADMISSION_REQUIRED"}` JSON. All responses are
`Cache-Control: no-store`. `/dev/session` polling does not extend learner idle expiry.

## Our own sign-in and sign-up (DLV-969, cloud mode)

Since 2026-11-02 the platform's sign-in and sign-up pages are our own; Cognito works behind them. Each route below is a
CSRF-protected `POST` under `/bff/api/v1/auth/password`, reachable without a sign-in (it creates one), with a body of at
most 8 KiB. Each calls exactly one Cognito user-pool operation as our confidential client (`SECRET_HASH`); these are
Cognito's unauthenticated client operations, so no IAM permission is involved. Tokens never leave the Gateway.

| Route | Body | Cognito | Answer (`data.step`) |
| --- | --- | --- | --- |
| `/sign-in` | `email`, `password`, `returnTo` | `InitiateAuth` `USER_PASSWORD_AUTH` | `SIGNED_IN` with `next`, or `NEW_PASSWORD`, `APP_CODE`, `EMAIL_CODE` |
| `/challenge` | `newPassword` or `code` | `RespondToAuthChallenge` (session kept server-side for 3 minutes) | as `/sign-in`; `STEP_EXPIRED` after 3 minutes or on replay |
| `/sign-up` | `firstName`, `lastName`, `email`, `password`, `returnTo` | `SignUp` (`email`, `given_name`, `family_name`, `name`) | `CODE_SENT` with the masked `destination` |
| `/sign-up/confirm` | `email`, `code`, `returnTo` | `ConfirmSignUp` | `SIGN_IN` (the password is never kept, so the person signs in once more) |
| `/sign-up/resend` | `email` | `ResendConfirmationCode` | `CODE_SENT` |
| `/password/forgot` | `email` | `ForgotPassword` | `CODE_SENT`, the same answer whether or not the account exists |
| `/password/reset` | `email`, `code`, `newPassword`, `returnTo` | `ConfirmForgotPassword`, then `InitiateAuth` with the new password | as `/sign-in` |

**Session.** A successful sign-in verifies the ID token (issuer, audience, signature, lifetime, `token_use=id`), rotates
the session id, saves an `OAuth2AuthenticationToken` with an `OidcUser` and an `OAuth2AuthorizedClient` (access and refresh
token) exactly as the OAuth callback does, and finishes through `GatewaySecurityHandlers.completeSignIn`: DEV gate
freshness, Domain admission, waiting accounts (`/dev/access?access=pending` in DEV, `/?access=pending` without the gate)
and sign-in challenges. The route returns the next path instead of redirecting. Refresh uses the existing token-endpoint
`refresh_token` grant, which Cognito accepts for refresh tokens from API sign-in.

**Domain.** Tokens from API sign-in carry only `aws.cognito.signin.user.admin`. Domain accepts exactly that scope only from
our client and only with the Gateway's proof (service secret on the internal sign-in routes, per-sign-in proof on API calls);
see Domain `CognitoTokenVerifier`.

**Errors** (`code`): `INVALID_CREDENTIALS` 401, `USER_NOT_CONFIRMED` 409, `CODE_MISMATCH` 400, `CODE_EXPIRED` 400,
`INVALID_PASSWORD` 400, `USERNAME_EXISTS` 409, `TOO_MANY_REQUESTS` 429, `STEP_EXPIRED` 400, `INVALID_REQUEST` 400,
`REQUEST_TOO_LARGE` 413, `SERVICE_UNAVAILABLE` 503. Cognito's own messages are never returned.

**Abuse controls.** Per Gateway task, in memory: 30 attempts per client address and 10 per account in 10 minutes (the
address is the last `X-Forwarded-For` hop when present). Cognito's own lockout stays behind it. Passwords and codes are
never logged or echoed.

**DEV gate.** Before admission the gate lets through only `GET`/`HEAD` of `/sign-in`, `/sign-up`, `/sign-in/forgot`,
`/sign-in/reset`, `/sign-in/new-password`, `/sign-in/code`, `/sign-up/confirm`, the favicon and the Web build's top-level
hashed bundles (`main|chunk|polyfills|styles|worker-<hash>.js|css`), plus `/api/v1/auth/options`, `/bff/api/v1/auth/csrf` and
`POST` of the seven routes above. Lesson assets, `/content/**`, every other page and API stay behind the gate. The gate
card's email button opens `/sign-in?returnTo=%2F`.
