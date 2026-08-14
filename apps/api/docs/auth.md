# Session authentication

Delivered by WO-003. Two credentials with different jobs and different risks.

| | Access token | Refresh token |
|---|---|---|
| Form | Signed JWT (HS256) | Opaque random string, 48 bytes url-safe |
| Lifetime | 15 minutes | 7 days |
| Transport | `Authorization: Bearer` header | HttpOnly cookie, `Path=/auth` |
| Stored | Nowhere — stateless | SHA-256 hash only |
| Client holds | In memory | Never readable by scripts |

Claims on the access token: `sub` (user), `tid` (tenant), `sid` (session),
`jti`, `typ`, `iat`, `exp`. The `typ` check means a future JWT of another kind
can never be presented as an access token.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/login` | Bootstrap a session. Sets the refresh cookie. |
| `POST` | `/auth/refresh` | Rotate the session, return a new access token. |
| `POST` | `/auth/logout` | Revoke the session. Idempotent. |
| `GET` | `/auth/me` | Resolve the caller. Requires a bearer token. |

## Rotation and replay

Every refresh rotates: the old session row is revoked and a new one replaces it.
A stolen refresh token is therefore useful only until the legitimate holder next
refreshes.

Presenting an already-revoked token is a **replay**, and it revokes *every*
active session for that user rather than merely failing the request. Two parties
are using one session lineage and we cannot tell which is the attacker; the safe
reading is that the lineage is compromised. The event is recorded as
`session.replay_detected`.

Consequence worth knowing: a legitimate user whose token was stolen gets logged
out of everything. That is the intended trade.

## Why the dependency hits the database

`get_current_actor` verifies the signature *and* re-checks the session row on
every request. Access tokens are stateless, so without that check a token issued
before a logout would keep working for up to fifteen more minutes. The cost is
one indexed primary-key lookup per request; the benefit is that logout and
replay-revocation take effect immediately.

## ⚠️ Bootstrap login is not authentication

`POST /auth/login` verifies **no secret**. The `users` table has no credential
column, and no work order currently covers password or OIDC login. Given a
tenant slug and the email of an active user, it issues a session.

Guards in place:

- Refused outright when `environment` is `production` or `prod`, regardless of
  the `allow_bootstrap_login` flag.
- `Settings.signing_secret_problems()` reports it as a production fault, along
  with a default or too-short signing key.
- The service requires the caller to pass `enabled` explicitly, so it cannot be
  reached by forgetting a check.

**Real authentication needs its own work order before any deployment reachable
by untrusted users.** Unknown-tenant and unknown-user responses are already
made indistinguishable so probing cannot enumerate tenants.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `FORGELAB_JWT_SECRET` | dev placeholder | Must be overridden in production; ≥32 chars |
| `FORGELAB_JWT_ALGORITHM` | `HS256` | |
| `FORGELAB_REFRESH_COOKIE_NAME` | `forgelab_refresh` | |
| `FORGELAB_REFRESH_COOKIE_PATH` | `/auth` | Keeps the cookie off ordinary API calls |
| `FORGELAB_REFRESH_COOKIE_SAMESITE` | `lax` | |
| `FORGELAB_REFRESH_COOKIE_SECURE` | unset | Unset means "secure unless local/test" |
| `FORGELAB_ALLOW_BOOTSTRAP_LOGIN` | `true` | Ignored in production |

Call `signing_secret_problems()` from a deployment preflight check — it returns
every fault at once rather than failing on the first.

## Adding an AuditAction

Adding a member to the `AuditAction` StrEnum does **not** change the database.
The `audit_action` CHECK constraint must be migrated by hand — Alembic's
autogenerate does not detect drift in non-native enum constraints. Migration
`a1c4e77b21d5` is the worked example.

`test_every_audit_action_value_is_accepted_by_the_database` fails loudly if this
step is skipped.
