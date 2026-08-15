"""Session lifecycle: issue, rotate, revoke.

Refresh tokens rotate on every use. The old row is revoked and a new one takes
its place, so a stolen refresh token is useful only until the legitimate holder
refreshes — at which point presenting the stolen copy is a *reuse* of a revoked
token, which is detectable.

On detecting reuse we revoke every active session for that user rather than
just rejecting the request. Either the attacker or the legitimate user holds a
token we already rotated away; we cannot tell which, and the safe reading of
"two parties are using one session lineage" is that the lineage is compromised.

Lookup by refresh token is deliberately *not* tenant-scoped: the cookie is the
only thing the caller presents, so the token hash has to identify the session on
its own. Token hashes are globally unique, and the tenant is read off the row
that is found — never supplied by the caller.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.audit import writer as audit
from forgelab_api.domains.constants import REFRESH_TOKEN_TTL, AuditAction, AuditOutcome
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import RefreshSession, Tenant, User
from forgelab_api.domains.identity.tokens import (
    AccessTokenClaims,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
)


class AuthenticationError(Exception):
    """Credentials were absent, unrecognised, expired, or withdrawn."""


class BootstrapDisabledError(Exception):
    """Bootstrap login was attempted where it is not permitted."""


@dataclass(frozen=True)
class IssuedSession:
    """Everything a caller needs after a successful login or refresh."""

    access_token: str
    refresh_token: str
    claims: AccessTokenClaims
    session_id: uuid.UUID
    user_id: uuid.UUID
    tenant_id: uuid.UUID


async def _get_tenant_by_slug(session: AsyncSession, slug: str) -> Tenant | None:
    result = await session.execute(select(Tenant).where(Tenant.slug == slug))
    return result.scalar_one_or_none()


async def _find_session_by_token(session: AsyncSession, token: str) -> RefreshSession | None:
    """Find a refresh session by token hash in any state, including revoked.

    Revoked rows must be reachable — a revoked row is exactly what reveals a
    replay attempt. `identity_repo.get_active_refresh_session` filters them out
    and is therefore the wrong tool here.
    """
    result = await session.execute(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(token))
    )
    return result.scalar_one_or_none()


async def _issue_session(
    session: AsyncSession,
    *,
    user: User,
    now: datetime,
    user_agent: str | None,
    ip_address: str | None,
) -> IssuedSession:
    """Create a refresh session row and a matching access token."""
    refresh_token = generate_refresh_token()
    record = RefreshSession(
        tenant_id=user.tenant_id,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        issued_at=now,
        expires_at=now + REFRESH_TOKEN_TTL,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    session.add(record)
    await session.flush()

    access_token, claims = create_access_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        session_id=record.id,
        now=now,
    )
    return IssuedSession(
        access_token=access_token,
        refresh_token=refresh_token,
        claims=claims,
        session_id=record.id,
        user_id=user.id,
        tenant_id=user.tenant_id,
    )


async def bootstrap_login(
    session: AsyncSession,
    *,
    tenant_slug: str,
    email: str,
    enabled: bool,
    user_agent: str | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> IssuedSession:
    """Issue a session for a known active user.

    This verifies no secret — there is no credential column to verify against.
    It exists so the dashboard and demo flows have a session before real
    authentication is built, and the caller must pass `enabled` explicitly so
    the affordance cannot be reached by accident.

    Raises:
        BootstrapDisabledError: bootstrap login is not permitted here.
        AuthenticationError: no such tenant, or no active user with that email.
    """
    if not enabled:
        raise BootstrapDisabledError("bootstrap login is disabled in this environment")

    moment = now or datetime.now(UTC)

    tenant = await _get_tenant_by_slug(session, tenant_slug)
    if tenant is None:
        # Deliberately indistinguishable from "no such user" — a caller should
        # not learn which tenants exist by probing.
        raise AuthenticationError("unknown tenant or user")

    user = await identity_repo.get_user_by_email(session, tenant_id=tenant.id, email=email)
    if user is None or not user.is_active:
        # The tenant resolved, so the attempt can be attributed somewhere. The
        # actor stays null: not knowing who tried is what makes this a failure.
        # Note the email is not recorded — a failed login is not a reason to
        # accumulate addresses supplied by unauthenticated callers.
        await audit.record_event(
            session,
            tenant_id=tenant.id,
            action=AuditAction.SESSION_DENIED,
            outcome=AuditOutcome.FAILURE,
            request_id=request_id,
            reason="no active user matched the supplied credentials",
            metadata={"method": "bootstrap"},
        )
        raise AuthenticationError("unknown tenant or user")

    issued = await _issue_session(
        session, user=user, now=moment, user_agent=user_agent, ip_address=ip_address
    )
    await audit.record_event(
        session,
        tenant_id=user.tenant_id,
        action=AuditAction.SESSION_ISSUED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=user.id,
        request_id=request_id,
        metadata={"session_id": str(issued.session_id), "method": "bootstrap"},
    )
    return issued


async def rotate_refresh_session(
    session: AsyncSession,
    *,
    refresh_token: str,
    user_agent: str | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> IssuedSession:
    """Exchange a refresh token for a new session, invalidating the old one.

    Raises:
        AuthenticationError: the token is unknown, expired, or already used.
    """
    moment = now or datetime.now(UTC)
    record = await _find_session_by_token(session, refresh_token)

    if record is None:
        raise AuthenticationError("refresh token is not recognised")

    if record.revoked_at is not None:
        # Someone is presenting a token we already rotated away. Assume the
        # lineage is compromised and end every session this user holds.
        await revoke_all_sessions_for_user(
            session, tenant_id=record.tenant_id, user_id=record.user_id, now=moment
        )
        await audit.record_event(
            session,
            tenant_id=record.tenant_id,
            action=AuditAction.SESSION_REPLAY_DETECTED,
            outcome=AuditOutcome.DENY,
            actor_user_id=record.user_id,
            request_id=request_id,
            reason="refresh token was already rotated; session lineage revoked",
            metadata={"session_id": str(record.id)},
        )
        raise AuthenticationError("refresh token has already been used")

    if record.expires_at <= moment:
        await audit.record_event(
            session,
            tenant_id=record.tenant_id,
            action=AuditAction.SESSION_DENIED,
            outcome=AuditOutcome.FAILURE,
            actor_user_id=record.user_id,
            request_id=request_id,
            reason="refresh token has expired",
            metadata={"session_id": str(record.id)},
        )
        raise AuthenticationError("refresh token has expired")

    user = await session.get(User, record.user_id)
    if user is None or not user.is_active:
        await audit.record_event(
            session,
            tenant_id=record.tenant_id,
            action=AuditAction.SESSION_DENIED,
            outcome=AuditOutcome.FAILURE,
            actor_user_id=record.user_id,
            request_id=request_id,
            reason="user is no longer active",
            metadata={"session_id": str(record.id)},
        )
        raise AuthenticationError("user is no longer active")

    record.revoked_at = moment
    await session.flush()

    issued = await _issue_session(
        session, user=user, now=moment, user_agent=user_agent, ip_address=ip_address
    )
    await audit.record_event(
        session,
        tenant_id=user.tenant_id,
        action=AuditAction.SESSION_REFRESHED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=user.id,
        request_id=request_id,
        metadata={"previous_session_id": str(record.id), "session_id": str(issued.session_id)},
    )
    return issued


async def revoke_all_sessions_for_user(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    now: datetime | None = None,
) -> int:
    """Revoke every active session for a user. Returns how many were revoked."""
    moment = now or datetime.now(UTC)
    active = await identity_repo.list_active_sessions_for_user(
        session, tenant_id=tenant_id, user_id=user_id, now=moment
    )
    for record in active:
        record.revoked_at = moment
    await session.flush()
    return len(active)


async def logout(
    session: AsyncSession,
    *,
    refresh_token: str,
    request_id: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Revoke the session behind a refresh token.

    Returns False when the token is unknown or already revoked. Logout is
    idempotent and never raises — telling an unauthenticated caller that their
    token was not recognised leaks more than it helps.
    """
    moment = now or datetime.now(UTC)
    record = await _find_session_by_token(session, refresh_token)
    if record is None or record.revoked_at is not None:
        return False

    record.revoked_at = moment
    await session.flush()
    await audit.record_event(
        session,
        tenant_id=record.tenant_id,
        action=AuditAction.SESSION_REVOKED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=record.user_id,
        request_id=request_id,
        metadata={"session_id": str(record.id)},
    )
    return True
