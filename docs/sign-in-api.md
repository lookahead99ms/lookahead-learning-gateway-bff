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
