"""Reusable request dependencies."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.db.session import get_session
from forgelab_api.domains.identity.models import RefreshSession
from forgelab_api.domains.identity.tokens import (
    ExpiredTokenError,
    InvalidTokenError,
    decode_access_token,
)

_UNAUTHENTICATED_HEADERS = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class Actor:
    """Who is making this request, and under which tenant."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    session_id: uuid.UUID


def _unauthenticated(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=_UNAUTHENTICATED_HEADERS,
    )


async def get_current_actor(
    authorization: Annotated[str | None, Header()] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = ...,  # type: ignore[assignment]
) -> Actor:
    """Resolve the actor from a bearer access token.

    The signature check alone is not sufficient. Access tokens are stateless, so
    a token issued before a logout stays cryptographically valid until it
    expires; the underlying session is therefore re-checked against the database
    on every request. That costs one indexed lookup per call and is what makes
    logout and replay-revocation take effect immediately rather than up to
    fifteen minutes later.
    """
    if not authorization:
        raise _unauthenticated("authorization header is missing")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthenticated("authorization header must be a bearer token")

    try:
        claims = decode_access_token(token)
    except ExpiredTokenError as exc:
        raise _unauthenticated("access token has expired") from exc
    except InvalidTokenError as exc:
        raise _unauthenticated("access token is not valid") from exc

    record = await session.get(RefreshSession, claims.session_id)
    if record is None:
        raise _unauthenticated("session no longer exists")
    if record.revoked_at is not None:
        raise _unauthenticated("session has been revoked")
    if record.expires_at <= datetime.now(UTC):
        raise _unauthenticated("session has expired")
    if record.tenant_id != claims.tenant_id or record.user_id != claims.user_id:
        # The token's claims disagree with the stored session. Treat as hostile.
        raise _unauthenticated("session does not match token claims")

    return Actor(
        user_id=claims.user_id,
        tenant_id=claims.tenant_id,
        session_id=claims.session_id,
    )


CurrentActor = Annotated[Actor, Depends(get_current_actor)]
