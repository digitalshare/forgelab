"""Audit records produced by the authentication routes, over HTTP.

The question these answer is not "was a row written" but "does the row let an
operator explain what happened, without containing anything that should not
survive the request".
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.core.config import get_settings
from forgelab_api.core.request_context import REQUEST_ID_HEADER
from forgelab_api.domains.audit.redaction import REDACTED
from forgelab_api.domains.constants import AuditAction, AuditOutcome
from forgelab_api.domains.identity.models import AuditEvent
from tests.identity_fixtures import IdentityFixture, seed_identity_graph

COOKIE_NAME = get_settings().refresh_cookie_name


@pytest.fixture
async def identity(db_session: AsyncSession) -> IdentityFixture:
    fixture = await seed_identity_graph(db_session)
    await db_session.commit()
    return fixture


async def _login(client: AsyncClient, identity: IdentityFixture, **headers: str):
    return await client.post(
        "/auth/login",
        json={
            "tenant_slug": identity.alpha.tenant.slug,
            "email": identity.alpha.owner.email,
        },
        headers=headers or None,
    )


async def _events(session: AsyncSession, identity: IdentityFixture) -> list[AuditEvent]:
    result = await session.execute(
        select(AuditEvent).where(AuditEvent.tenant_id == identity.alpha.tenant.id)
    )
    return list(result.scalars().all())


def _by_action(events: list[AuditEvent], action: AuditAction) -> list[AuditEvent]:
    return [e for e in events if e.action is action]


# --------------------------------------------------------------------------
# Successful flows
# --------------------------------------------------------------------------


async def test_login_records_a_permit(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity)
    issued = _by_action(await _events(db_session, identity), AuditAction.SESSION_ISSUED)

    assert issued
    assert issued[0].outcome is AuditOutcome.PERMIT
    assert issued[0].actor_user_id == identity.alpha.owner.id


async def test_refresh_records_a_permit(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity)
    await api_client.post("/auth/refresh")

    refreshed = _by_action(await _events(db_session, identity), AuditAction.SESSION_REFRESHED)
    assert refreshed
    assert refreshed[0].outcome is AuditOutcome.PERMIT


async def test_logout_records_a_permit(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity)
    await api_client.post("/auth/logout")

    revoked = _by_action(await _events(db_session, identity), AuditAction.SESSION_REVOKED)
    assert revoked
    assert revoked[0].outcome is AuditOutcome.PERMIT


# --------------------------------------------------------------------------
# Rejected flows
# --------------------------------------------------------------------------


async def test_failed_login_is_recorded_with_a_reason(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """The attempt must survive the rejection, or nobody can see it happened."""
    await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": "nobody@alpha.example"},
    )

    denied = _by_action(await _events(db_session, identity), AuditAction.SESSION_DENIED)
    assert denied
    assert denied[0].outcome is AuditOutcome.FAILURE
    assert denied[0].reason
    assert denied[0].actor_user_id is None


async def test_failed_login_does_not_record_the_attempted_email(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """A failed login is not a reason to accumulate unauthenticated input."""
    await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": "probe@alpha.example"},
    )

    events = await _events(db_session, identity)
    assert "probe@alpha.example" not in str([e.event_metadata for e in events])


async def test_replay_rejection_is_recorded_as_a_deny(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    stale = login.cookies[COOKIE_NAME]
    await api_client.post("/auth/refresh")

    api_client.cookies.set(COOKIE_NAME, stale, path="/auth")
    await api_client.post("/auth/refresh")

    replay = _by_action(
        await _events(db_session, identity), AuditAction.SESSION_REPLAY_DETECTED
    )
    assert replay
    assert replay[0].outcome is AuditOutcome.DENY
    assert replay[0].reason


async def test_deny_and_failure_are_distinguishable(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """A refused decision and an unevaluable attempt are different questions."""
    login = await _login(api_client, identity)
    stale = login.cookies[COOKIE_NAME]
    await api_client.post("/auth/refresh")
    api_client.cookies.set(COOKIE_NAME, stale, path="/auth")
    await api_client.post("/auth/refresh")

    await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": "nobody@alpha.example"},
    )

    outcomes = {e.outcome for e in await _events(db_session, identity)}
    assert AuditOutcome.DENY in outcomes
    assert AuditOutcome.FAILURE in outcomes


# --------------------------------------------------------------------------
# No credential material
# --------------------------------------------------------------------------


async def test_no_audit_record_contains_the_refresh_token(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    token = login.cookies[COOKIE_NAME]
    await api_client.post("/auth/refresh")
    await api_client.post("/auth/logout")

    serialized = str([(e.event_metadata, e.reason) for e in await _events(db_session, identity)])
    assert token not in serialized


async def test_no_audit_record_contains_an_access_token(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    access = (await _login(api_client, identity)).json()["access_token"]
    serialized = str([(e.event_metadata, e.reason) for e in await _events(db_session, identity)])
    assert access not in serialized


async def test_metadata_never_carries_a_token_hash(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """`token_hash` is a sensitive key, so it is redacted even if a caller adds it."""
    await _login(api_client, identity)
    for event in await _events(db_session, identity):
        for key, value in event.event_metadata.items():
            if "token" in key.lower():
                assert value == REDACTED


# --------------------------------------------------------------------------
# Request correlation
# --------------------------------------------------------------------------


async def test_events_carry_the_request_identifier(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    response = await _login(api_client, identity)
    request_id = response.headers[REQUEST_ID_HEADER]

    issued = _by_action(await _events(db_session, identity), AuditAction.SESSION_ISSUED)
    assert issued[0].request_id == request_id


async def test_a_supplied_request_identifier_is_honoured(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity, **{REQUEST_ID_HEADER: "trace-12345"})

    issued = _by_action(await _events(db_session, identity), AuditAction.SESSION_ISSUED)
    assert issued[0].request_id == "trace-12345"


async def test_a_malformed_request_identifier_is_replaced(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """The value is stored and echoed, so caller input cannot be taken on trust."""
    hostile = "x" * 200 + "\r\nInjected: yes"
    response = await _login(api_client, identity, **{REQUEST_ID_HEADER: hostile})

    assert response.headers[REQUEST_ID_HEADER] != hostile
    issued = _by_action(await _events(db_session, identity), AuditAction.SESSION_ISSUED)
    assert issued[0].request_id is not None
    assert "Injected" not in issued[0].request_id


async def test_every_response_carries_a_request_identifier(api_client: AsyncClient):
    response = await api_client.get("/healthz")
    assert response.headers[REQUEST_ID_HEADER]


async def test_one_request_produces_one_identifier_across_its_events(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """Correlation is the point — timestamps cannot separate same-transaction rows."""
    login = await _login(api_client, identity)
    first = login.headers[REQUEST_ID_HEADER]

    refresh = await api_client.post("/auth/refresh")
    second = refresh.headers[REQUEST_ID_HEADER]

    assert first != second
    events = await _events(db_session, identity)
    ids = {e.request_id for e in events if e.request_id}
    assert {first, second} <= ids
