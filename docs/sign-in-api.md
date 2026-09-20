# Logical sign-in API source notes

DLV-920 Gateway mappings below are exact, with no wildcard forwarding. Identity owns authentication, account ownership, CSRF and durable admission/revocation. Requests use Identity CSRF obtained from `/api/v1/auth/csrf`, including the restricted challenge flow; the BFF CSRF token is different.

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

These are Gateway source notes for the private generated API reference. Identity defines the authoritative inventory/challenge response schemas and error catalogue. Full cross-service admission/concurrency verification remains a release gate owned by the parent DLV-920 work; Gateway unit/transport tests alone do not prove it.
