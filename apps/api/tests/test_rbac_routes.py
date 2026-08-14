"""RBAC enforcement over HTTP, through real routing and the auth dependency."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import PolicyDecisionOutcome, RefreshSession
from forgelab_api.domains.identity.tokens import create_access_token
from tests.rbac_fixtures import RbacFixture, seed_rbac_graph


@pytest.fixture
async def rbac(db_session: AsyncSession) -> RbacFixture:
    fixture = await seed_rbac_graph(db_session)
    await db_session.commit()
    return fixture


async def _token_for(db_session: AsyncSession, user, tenant_id: uuid.UUID) -> str:
    """Mint a live session and access token for a user.

    Goes through the real session table rather than signing a bare token, so
    `get_current_actor`'s session check passes and these tests exercise the
    genuine authentication path ahead of authorization.
    """
    from datetime import UTC, datetime, timedelta

    record = RefreshSession(
        tenant_id=tenant_id,
        user_id=user.id,
        token_hash=f"rbac-{uuid.uuid4().hex}",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(record)
    await db_session.flush()
    await db_session.commit()

    token, _ = create_access_token(
        user_id=user.id, tenant_id=tenant_id, session_id=record.id
    )
    return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _url(project_id: uuid.UUID, path: str) -> str:
    return f"/projects/{project_id}/{path}"


# --------------------------------------------------------------------------
# Allowed access
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role_attr", ["owner", "maintainer"])
async def test_admin_roles_reach_an_admin_route(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture, role_attr: str
):
    user = getattr(rbac, role_attr)
    token = await _token_for(db_session, user, rbac.identity.alpha.tenant.id)

    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "admin-action"), headers=_auth(token)
    )
    assert response.status_code == 200
    assert response.json()["handler_ran"] is True


@pytest.mark.parametrize("role_attr", ["owner", "maintainer", "reviewer", "operator"])
async def test_every_role_reaches_an_any_member_route(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture, role_attr: str
):
    user = getattr(rbac, role_attr)
    token = await _token_for(db_session, user, rbac.identity.alpha.tenant.id)

    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"), headers=_auth(token)
    )
    assert response.status_code == 200


async def test_response_reports_the_actors_role(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.reviewer, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "reviewer-action"), headers=_auth(token)
    )
    assert response.status_code == 200
    assert response.json()["role"] == ProjectRole.REVIEWER.value


async def test_operator_only_route_admits_the_operator(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.operator, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "operator-action"), headers=_auth(token)
    )
    assert response.status_code == 200


# --------------------------------------------------------------------------
# Denied access
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role_attr", ["reviewer", "operator"])
async def test_wrong_role_gets_403(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture, role_attr: str
):
    """A member with the wrong role learns only that their role is insufficient."""
    user = getattr(rbac, role_attr)
    token = await _token_for(db_session, user, rbac.identity.alpha.tenant.id)

    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "admin-action"), headers=_auth(token)
    )
    assert response.status_code == 403


async def test_owner_is_denied_a_reviewer_only_route(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """No hierarchy: Owner does not inherit Reviewer."""
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "reviewer-action"), headers=_auth(token)
    )
    assert response.status_code == 403


async def test_non_member_gets_404_not_403(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """403 would confirm the project exists; 404 tells them nothing."""
    token = await _token_for(db_session, rbac.non_member, rbac.identity.alpha.tenant.id)
    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"), headers=_auth(token)
    )
    assert response.status_code == 404


async def test_revoked_member_gets_404(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.revoked_member, rbac.identity.alpha.tenant.id)
    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"), headers=_auth(token)
    )
    assert response.status_code == 404


async def test_cross_tenant_request_gets_404(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """Beta's owner holds a genuine session and a genuine membership elsewhere."""
    token = await _token_for(db_session, rbac.foreign_user, rbac.identity.beta.tenant.id)
    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"), headers=_auth(token)
    )
    assert response.status_code == 404


async def test_cross_project_request_gets_404(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """Same tenant, same user, different project — membership does not carry."""
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.get(
        _url(rbac.other_project.id, "any-member-action"), headers=_auth(token)
    )
    assert response.status_code == 404


async def test_unknown_project_gets_404(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.get(_url(uuid.uuid4(), "any-member-action"), headers=_auth(token))
    assert response.status_code == 404


# --------------------------------------------------------------------------
# Authentication still comes first
# --------------------------------------------------------------------------


async def test_unauthenticated_request_gets_401(rbac_client: AsyncClient, rbac: RbacFixture):
    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action")
    )
    assert response.status_code == 401


async def test_garbage_token_gets_401(rbac_client: AsyncClient, rbac: RbacFixture):
    response = await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"),
        headers=_auth("not.a.real.token"),
    )
    assert response.status_code == 401


async def test_authentication_is_checked_before_authorization(
    rbac_client: AsyncClient, rbac: RbacFixture
):
    """An unauthenticated request to an unknown project is 401, not 404."""
    response = await rbac_client.get(_url(uuid.uuid4(), "any-member-action"))
    assert response.status_code == 401


async def test_malformed_project_id_is_rejected_as_a_bad_request(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.get(
        "/projects/not-a-uuid/any-member-action", headers=_auth(token)
    )
    assert response.status_code == 422


# --------------------------------------------------------------------------
# Enforcement precedes the handler, and decisions survive
# --------------------------------------------------------------------------


async def test_denied_request_never_reaches_the_handler(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.reviewer, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "admin-action"), headers=_auth(token)
    )
    assert response.status_code == 403
    assert "handler_ran" not in response.json()


async def test_denied_decision_survives_the_failed_request(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """The handler never ran, so nothing else would have committed the record."""
    token = await _token_for(db_session, rbac.reviewer, rbac.identity.alpha.tenant.id)
    await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "admin-action"), headers=_auth(token)
    )

    decisions = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.DENY,
    )
    assert any(d.actor_user_id == rbac.reviewer.id for d in decisions)


async def test_allowed_decision_is_recorded_over_http(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    await rbac_client.post(
        _url(rbac.identity.alpha.project.id, "admin-action"), headers=_auth(token)
    )

    decisions = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.ALLOW,
    )
    assert any(d.actor_user_id == rbac.owner.id for d in decisions)


async def test_cross_tenant_denial_is_recorded_against_the_caller(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.foreign_user, rbac.identity.beta.tenant.id)
    await rbac_client.get(
        _url(rbac.identity.alpha.project.id, "any-member-action"), headers=_auth(token)
    )

    decisions = await identity_repo.list_policy_decisions(
        db_session, tenant_id=rbac.identity.beta.tenant.id
    )
    assert any(d.actor_user_id == rbac.foreign_user.id for d in decisions)
