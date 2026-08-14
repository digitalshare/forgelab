"""Integration tests for the auth routes and the authentication dependency.

Exercised end to end over HTTP against a real database: login, refresh
rotation, replay rejection, logout revocation, and protected-endpoint access.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.core.config import get_settings
from forgelab_api.domains.constants import ACCESS_TOKEN_TTL, ACCESS_TOKEN_TTL_SECONDS, AuditAction
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity import service as identity_service
from forgelab_api.domains.identity.models import RefreshSession
from forgelab_api.domains.identity.tokens import create_access_token, hash_refresh_token
from tests.identity_fixtures import IdentityFixture, seed_identity_graph

COOKIE_NAME = get_settings().refresh_cookie_name


@pytest.fixture
async def identity(db_session: AsyncSession) -> IdentityFixture:
    fixture = await seed_identity_graph(db_session)
    await db_session.commit()
    return fixture


async def _login(client: AsyncClient, identity: IdentityFixture):
    return await client.post(
        "/auth/login",
        json={
            "tenant_slug": identity.alpha.tenant.slug,
            "email": identity.alpha.owner.email,
        },
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# Login
# --------------------------------------------------------------------------


async def test_login_returns_an_access_token_and_sets_a_refresh_cookie(
    api_client: AsyncClient, identity: IdentityFixture
):
    response = await _login(api_client, identity)
    assert response.status_code == 200

    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == ACCESS_TOKEN_TTL_SECONDS == 900
    assert body["tenant_id"] == str(identity.alpha.tenant.id)
    assert body["user_id"] == str(identity.alpha.owner.id)
    assert body["access_token"]

    assert COOKIE_NAME in response.cookies


async def test_refresh_cookie_is_httponly_and_scoped_to_auth(
    api_client: AsyncClient, identity: IdentityFixture
):
    """The refresh credential must be unreadable by scripts and narrowly scoped."""
    response = await _login(api_client, identity)
    header = response.headers["set-cookie"].lower()
    assert "httponly" in header
    assert "path=/auth" in header
    assert "samesite=lax" in header


async def test_login_rejects_an_unknown_email(api_client: AsyncClient, identity: IdentityFixture):
    response = await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": "nobody@alpha.example"},
    )
    assert response.status_code == 401


async def test_login_rejects_an_unknown_tenant(api_client: AsyncClient, identity: IdentityFixture):
    response = await api_client.post(
        "/auth/login",
        json={"tenant_slug": "no-such-tenant", "email": identity.alpha.owner.email},
    )
    assert response.status_code == 401


async def test_unknown_tenant_and_unknown_user_are_indistinguishable(
    api_client: AsyncClient, identity: IdentityFixture
):
    """Probing must not reveal which tenants exist."""
    unknown_tenant = await api_client.post(
        "/auth/login",
        json={"tenant_slug": "no-such-tenant", "email": identity.alpha.owner.email},
    )
    unknown_user = await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": "nobody@alpha.example"},
    )
    assert unknown_tenant.json() == unknown_user.json()


async def test_login_will_not_cross_tenants(api_client: AsyncClient, identity: IdentityFixture):
    """Beta's user must not authenticate through Alpha's tenant."""
    response = await api_client.post(
        "/auth/login",
        json={"tenant_slug": identity.alpha.tenant.slug, "email": identity.beta.owner.email},
    )
    assert response.status_code == 401


async def test_login_rejects_an_inactive_user(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    identity.alpha.owner.is_active = False
    await db_session.commit()

    assert (await _login(api_client, identity)).status_code == 401


async def test_login_records_an_audit_event(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity)
    events = await identity_repo.list_audit_events(
        db_session, tenant_id=identity.alpha.tenant.id
    )
    assert AuditAction.SESSION_ISSUED in {e.action for e in events}


# --------------------------------------------------------------------------
# Protected access
# --------------------------------------------------------------------------


async def test_protected_endpoint_resolves_the_actor(
    api_client: AsyncClient, identity: IdentityFixture
):
    token = (await _login(api_client, identity)).json()["access_token"]
    response = await api_client.get("/auth/me", headers=_auth(token))

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == str(identity.alpha.owner.id)
    assert body["tenant_id"] == str(identity.alpha.tenant.id)


async def test_protected_endpoint_rejects_a_missing_header(api_client: AsyncClient):
    response = await api_client.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic abc123", "token abc123", "abc123"],
)
async def test_protected_endpoint_rejects_malformed_authorization(
    api_client: AsyncClient, header: str
):
    response = await api_client.get("/auth/me", headers={"Authorization": header})
    assert response.status_code == 401


async def test_protected_endpoint_rejects_a_garbage_token(api_client: AsyncClient):
    assert (await api_client.get("/auth/me", headers=_auth("not.a.token"))).status_code == 401


async def test_protected_endpoint_rejects_an_expired_token(
    api_client: AsyncClient, identity: IdentityFixture
):
    expired, _ = create_access_token(
        user_id=identity.alpha.owner.id,
        tenant_id=identity.alpha.tenant.id,
        session_id=identity.alpha.session.id,
        now=datetime.now(UTC) - ACCESS_TOKEN_TTL - timedelta(minutes=1),
    )
    assert (await api_client.get("/auth/me", headers=_auth(expired))).status_code == 401


async def test_token_for_an_unknown_session_is_rejected(
    api_client: AsyncClient, identity: IdentityFixture
):
    import uuid

    orphan, _ = create_access_token(
        user_id=identity.alpha.owner.id,
        tenant_id=identity.alpha.tenant.id,
        session_id=uuid.uuid4(),
    )
    assert (await api_client.get("/auth/me", headers=_auth(orphan))).status_code == 401


async def test_token_whose_claims_disagree_with_the_session_is_rejected(
    api_client: AsyncClient, identity: IdentityFixture
):
    """A valid signature over the wrong tenant must not authenticate."""
    mismatched, _ = create_access_token(
        user_id=identity.alpha.owner.id,
        tenant_id=identity.beta.tenant.id,
        session_id=identity.alpha.session.id,
    )
    assert (await api_client.get("/auth/me", headers=_auth(mismatched))).status_code == 401


# --------------------------------------------------------------------------
# Refresh rotation and replay
# --------------------------------------------------------------------------


async def test_refresh_rotates_the_cookie_and_returns_a_new_token(
    api_client: AsyncClient, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    original_cookie = login.cookies[COOKIE_NAME]

    refreshed = await api_client.post("/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.cookies[COOKIE_NAME] != original_cookie
    assert refreshed.json()["access_token"]


async def test_refresh_revokes_the_previous_session_row(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    previous = login.cookies[COOKIE_NAME]

    await api_client.post("/auth/refresh")

    record = await db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(previous))
    )
    assert record is not None
    assert record.revoked_at is not None


async def test_replaying_a_rotated_refresh_token_is_rejected(
    api_client: AsyncClient, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    stale = login.cookies[COOKIE_NAME]

    await api_client.post("/auth/refresh")

    api_client.cookies.set(COOKIE_NAME, stale, path="/auth")
    replay = await api_client.post("/auth/refresh")
    assert replay.status_code == 401


async def test_replay_revokes_every_session_the_user_holds(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    """Two parties holding one lineage means the lineage is compromised."""
    login = await _login(api_client, identity)
    stale = login.cookies[COOKIE_NAME]
    current_token = (await api_client.post("/auth/refresh")).json()["access_token"]

    assert (await api_client.get("/auth/me", headers=_auth(current_token))).status_code == 200

    api_client.cookies.set(COOKIE_NAME, stale, path="/auth")
    await api_client.post("/auth/refresh")

    # The still-valid access token must stop working now the lineage is burned.
    assert (await api_client.get("/auth/me", headers=_auth(current_token))).status_code == 401

    remaining = await identity_repo.list_active_sessions_for_user(
        db_session, tenant_id=identity.alpha.tenant.id, user_id=identity.alpha.owner.id
    )
    assert list(remaining) == []


async def test_replay_is_recorded_for_audit(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    stale = login.cookies[COOKIE_NAME]
    await api_client.post("/auth/refresh")
    api_client.cookies.set(COOKIE_NAME, stale, path="/auth")
    await api_client.post("/auth/refresh")

    events = await identity_repo.list_audit_events(
        db_session, tenant_id=identity.alpha.tenant.id
    )
    assert AuditAction.SESSION_REPLAY_DETECTED in {e.action for e in events}


async def test_refresh_without_a_cookie_is_rejected(api_client: AsyncClient):
    assert (await api_client.post("/auth/refresh")).status_code == 401


async def test_refresh_with_an_unknown_token_is_rejected(api_client: AsyncClient):
    api_client.cookies.set(COOKIE_NAME, "not-a-real-refresh-token", path="/auth")
    response = await api_client.post("/auth/refresh")
    assert response.status_code == 401


async def test_expired_refresh_token_is_rejected(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    login = await _login(api_client, identity)
    token = login.cookies[COOKIE_NAME]

    record = await db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(token))
    )
    assert record is not None
    record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    assert (await api_client.post("/auth/refresh")).status_code == 401


# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------


async def test_logout_revokes_the_session(api_client: AsyncClient, identity: IdentityFixture):
    await _login(api_client, identity)
    response = await api_client.post("/auth/logout")

    assert response.status_code == 200
    assert response.json()["revoked"] is True


async def test_refresh_after_logout_fails(api_client: AsyncClient, identity: IdentityFixture):
    login = await _login(api_client, identity)
    token = login.cookies[COOKIE_NAME]

    await api_client.post("/auth/logout")

    api_client.cookies.set(COOKIE_NAME, token, path="/auth")
    assert (await api_client.post("/auth/refresh")).status_code == 401


async def test_access_token_stops_working_after_logout(
    api_client: AsyncClient, identity: IdentityFixture
):
    """Stateless tokens would otherwise stay valid for their full 15 minutes."""
    access = (await _login(api_client, identity)).json()["access_token"]
    assert (await api_client.get("/auth/me", headers=_auth(access))).status_code == 200

    await api_client.post("/auth/logout")

    assert (await api_client.get("/auth/me", headers=_auth(access))).status_code == 401


async def test_logout_is_idempotent(api_client: AsyncClient, identity: IdentityFixture):
    await _login(api_client, identity)
    first = await api_client.post("/auth/logout")
    second = await api_client.post("/auth/logout")

    assert first.json()["revoked"] is True
    assert second.status_code == 200
    assert second.json()["revoked"] is False


async def test_logout_without_a_cookie_succeeds_quietly(api_client: AsyncClient):
    response = await api_client.post("/auth/logout")
    assert response.status_code == 200
    assert response.json()["revoked"] is False


async def test_logout_records_an_audit_event(
    api_client: AsyncClient, db_session: AsyncSession, identity: IdentityFixture
):
    await _login(api_client, identity)
    await api_client.post("/auth/logout")

    events = await identity_repo.list_audit_events(
        db_session, tenant_id=identity.alpha.tenant.id
    )
    assert AuditAction.SESSION_REVOKED in {e.action for e in events}


# --------------------------------------------------------------------------
# Bootstrap gating
# --------------------------------------------------------------------------


async def test_bootstrap_login_is_refused_when_disabled(
    db_session: AsyncSession, identity: IdentityFixture
):
    with pytest.raises(identity_service.BootstrapDisabledError):
        await identity_service.bootstrap_login(
            db_session,
            tenant_slug=identity.alpha.tenant.slug,
            email=identity.alpha.owner.email,
            enabled=False,
        )
