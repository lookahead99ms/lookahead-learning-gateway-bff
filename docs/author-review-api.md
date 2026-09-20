# Author review proxy

The BFF forwards these exact routes to the fixed Domain API origin. Domain owns
the version-bound artifact manifest, author-capability checks and append-only
PostgreSQL review history. Gateway never reads or changes delivery-board files.

| Browser route | Method | Domain route |
| --- | --- | --- |
| `/bff/api/v1/author/review-artifacts` | GET | `/api/v1/author/review-artifacts` |
| `/bff/api/v1/author/review-artifacts/{artifactId}/events` | GET | `/api/v1/author/review-artifacts/{artifactId}/events` |
| `/bff/api/v1/author/review-artifacts/{artifactId}/events` | POST | `/api/v1/author/review-artifacts/{artifactId}/events` |

Artifact IDs match `[a-z0-9][a-z0-9-]{0,79}`. Other author paths and methods are
not added to the proxy allowlist. History GET preserves the encoded `limit` and
`cursor` query for Domain validation. POST rejects any query string and accepts
at most 16 KiB. Domain validates JSON fields, decisions, artifact version/hash,
owning ticket, idempotency and supersession.

The submit body contains `artifactVersion`, `contentHash`, `ticketId`, `decision`
(`APPROVE`, `DECLINE`, `NEED_MORE`), `comment` and optional/null
`supersedesEventId`. Supply the UUID `Idempotency-Key` header for safe retry.
Decisions and comments are recorded as review events; they do not merge code or
change ticket status. A successful response indicates pending Main reconciliation.
Consult the Domain API OpenAPI document for authoritative DTOs and error codes.

The browser first completes the ordinary OAuth login and obtains a session-bound
CSRF token from `GET /bff/api/v1/auth/csrf`. POST requires that token's header and
the same BFF session. The BFF supplies its server-held access token to Domain;
browser Authorization and Cookie headers are never relayed to Domain. Anonymous
requests return 401; missing or another session's CSRF token returns 403. A valid
BFF session alone does not confer author permission: Domain enforces that grant.

Domain statuses and JSON envelopes pass through unchanged, including stale-version,
authorization and idempotency errors. Oversized request bodies return 413 and
unsupported routes or POST query strings return 404. Responses use `no-store`.
This change adds no service, database, cookie, secret or runtime configuration.

Validation: `./gradlew test --offline` covers canonical route matching, request
bounds, encoded query forwarding, server-only bearer injection, idempotency header
forwarding, Domain error preservation and the real Gateway session/CSRF chain.
These tests use a stub Domain; they do not prove cross-service database persistence.
