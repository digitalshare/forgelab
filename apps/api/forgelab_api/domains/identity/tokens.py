"""Access-token signing and refresh-token generation.

Two different kinds of credential, deliberately built differently:

* **Access tokens** are signed JWTs carrying tenant, actor, and session. They
  are short-lived because they are stateless — nothing can be withdrawn from a
  token already in someone's hands except by waiting for it to expire.
* **Refresh tokens** are opaque random strings. Only a SHA-256 hash is stored,
  so a database disclosure yields nothing usable. They are not JWTs because
  there is no reason to put readable claims in a credential whose only job is
  to be looked up server-side.

Pure functions only — no database access, no I/O. Rotation lives in `service`.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from forgelab_api.core.config import get_settings
from forgelab_api.domains.constants import ACCESS_TOKEN_TTL

#: Distinguishes an access token from any other JWT this system may later sign,
#: so one kind of credential can never be presented as another.
ACCESS_TOKEN_TYPE = "access"

#: A refresh token's entropy. 48 bytes url-safe ≈ 64 characters.
_REFRESH_TOKEN_BYTES = 48


class TokenError(Exception):
    """Base class for credential rejection."""


class ExpiredTokenError(TokenError):
    """The token was well-formed and correctly signed, but has expired."""


class InvalidTokenError(TokenError):
    """The token was missing, malformed, mis-signed, or of the wrong type."""


@dataclass(frozen=True)
class AccessTokenClaims:
    """Verified contents of an access token."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    session_id: uuid.UUID
    token_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime


def create_access_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session_id: uuid.UUID,
    now: datetime | None = None,
    ttl: timedelta | None = None,
) -> tuple[str, AccessTokenClaims]:
    """Sign an access token and return it alongside its claims.

    `now` and `ttl` are injectable so expiry behaviour can be tested without
    sleeping or freezing the clock.
    """
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + (ttl if ttl is not None else ACCESS_TOKEN_TTL)
    token_id = uuid.uuid4()

    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "sid": str(session_id),
        "jti": str(token_id),
        "typ": ACCESS_TOKEN_TYPE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    return token, AccessTokenClaims(
        user_id=user_id,
        tenant_id=tenant_id,
        session_id=session_id,
        token_id=token_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def decode_access_token(token: str) -> AccessTokenClaims:
    """Verify signature, expiry, and type, returning the claims.

    Raises:
        ExpiredTokenError: the token has passed its expiry.
        InvalidTokenError: anything else wrong with it.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "tid", "sid", "jti", "typ", "iat", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError("access token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(f"access token is not valid: {exc}") from exc

    if payload.get("typ") != ACCESS_TOKEN_TYPE:
        raise InvalidTokenError("token is not an access token")

    try:
        return AccessTokenClaims(
            user_id=uuid.UUID(payload["sub"]),
            tenant_id=uuid.UUID(payload["tid"]),
            session_id=uuid.UUID(payload["sid"]),
            token_id=uuid.UUID(payload["jti"]),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidTokenError("access token claims are malformed") from exc


def generate_refresh_token() -> str:
    """A fresh opaque refresh token. Returned once and never stored in the clear."""
    return secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Hash a refresh token for storage and lookup.

    Plain SHA-256 rather than a slow KDF: these are 384 bits of generated
    entropy, not user-chosen passwords, so there is no dictionary to attack and
    nothing to gain from deliberate slowness on a per-request lookup.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
