"""Authorization logic tests, exercised directly against the service."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import ProjectAction, ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import MembershipStatus, PolicyDecisionOutcome
from forgelab_api.domains.policy.rbac import (
    ADMIN_ROLES,
    ALL_ROLES,
    AuthorizationDenied,
    DenyReason,
    authorize_project_action,
)
from tests.rbac_fixtures import RbacFixture, seed_rbac_graph

ACTION = ProjectAction.CONNECT_REPOSITORY


@pytest.fixture
async def rbac(db_session: AsyncSession) -> RbacFixture:
    return await seed_rbac_graph(db_session)


async def _authorize(
    session: AsyncSession,
    rbac: RbacFixture,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    allowed_roles: tuple[ProjectRole, ...] = ADMIN_ROLES,
):
    return await authorize_project_action(
        session,
        actor_user_id=user_id,
        tenant_id=tenant_id or rbac.identity.alpha.tenant.id,
        project_id=project_id or rbac.identity.alpha.project.id,
        action=ACTION,
        allowed_roles=allowed_roles,
    )


# --------------------------------------------------------------------------
# Role matching
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role_attr", ["owner", "maintainer"])
async def test_permitted_roles_are_authorized(
    db_session: AsyncSession, rbac: RbacFixture, role_attr: str
):
    user = getattr(rbac, role_attr)
    context = await _authorize(db_session, rbac, user_id=user.id)
    assert context.project_id == rbac.identity.alpha.project.id
    assert context.action is ACTION


@pytest.mark.parametrize("role_attr", ["reviewer", "operator"])
async def test_unlisted_roles_are_denied(
    db_session: AsyncSession, rbac: RbacFixture, role_attr: str
):
    user = getattr(rbac, role_attr)
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(db_session, rbac, user_id=user.id)
    assert exc.value.reason is DenyReason.ROLE_NOT_PERMITTED


async def test_every_role_passes_when_all_roles_are_accepted(
    db_session: AsyncSession, rbac: RbacFixture
):
    for user in (rbac.owner, rbac.maintainer, rbac.reviewer, rbac.operator):
        context = await _authorize(db_session, rbac, user_id=user.id, allowed_roles=ALL_ROLES)
        assert context.role in ALL_ROLES


async def test_owner_is_not_implicitly_granted_another_role(
    db_session: AsyncSession, rbac: RbacFixture
):
    """There is no hierarchy — an Owner is denied where only Reviewer is listed."""
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(
            db_session, rbac, user_id=rbac.owner.id, allowed_roles=(ProjectRole.REVIEWER,)
        )
    assert exc.value.reason is DenyReason.ROLE_NOT_PERMITTED


async def test_context_reports_the_actual_role(db_session: AsyncSession, rbac: RbacFixture):
    context = await _authorize(
        db_session, rbac, user_id=rbac.operator.id, allowed_roles=ALL_ROLES
    )
    assert context.role is ProjectRole.OPERATOR


# --------------------------------------------------------------------------
# Membership
# --------------------------------------------------------------------------


async def test_non_member_is_denied_without_admitting_the_project_exists(
    db_session: AsyncSession, rbac: RbacFixture
):
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(db_session, rbac, user_id=rbac.non_member.id, allowed_roles=ALL_ROLES)
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


async def test_revoked_membership_is_denied(db_session: AsyncSession, rbac: RbacFixture):
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(
            db_session, rbac, user_id=rbac.revoked_member.id, allowed_roles=ALL_ROLES
        )
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


async def test_revoking_a_membership_removes_access(
    db_session: AsyncSession, rbac: RbacFixture
):
    assert await _authorize(db_session, rbac, user_id=rbac.maintainer.id)

    membership = await identity_repo.get_active_membership(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        project_id=rbac.identity.alpha.project.id,
        user_id=rbac.maintainer.id,
    )
    assert membership is not None
    membership.status = MembershipStatus.REVOKED
    await db_session.flush()

    with pytest.raises(AuthorizationDenied):
        await _authorize(db_session, rbac, user_id=rbac.maintainer.id)


async def test_unknown_project_is_denied(db_session: AsyncSession, rbac: RbacFixture):
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(
            db_session, rbac, user_id=rbac.owner.id, project_id=uuid.uuid4()
        )
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


# --------------------------------------------------------------------------
# Tenant and project isolation
# --------------------------------------------------------------------------


async def test_membership_does_not_carry_to_another_project(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Owner of one project is a stranger to the next one in the same tenant."""
    with pytest.raises(AuthorizationDenied) as exc:
        await _authorize(
            db_session,
            rbac,
            user_id=rbac.owner.id,
            project_id=rbac.other_project.id,
            allowed_roles=ALL_ROLES,
        )
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


async def test_a_valid_session_in_another_tenant_grants_nothing(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Beta's owner has a real membership — just not in this tenant."""
    with pytest.raises(AuthorizationDenied) as exc:
        await authorize_project_action(
            db_session,
            actor_user_id=rbac.foreign_user.id,
            tenant_id=rbac.identity.beta.tenant.id,
            project_id=rbac.identity.alpha.project.id,
            action=ACTION,
            allowed_roles=ALL_ROLES,
        )
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


async def test_claiming_another_tenants_id_does_not_help(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Presenting Alpha's tenant with Beta's user resolves no membership."""
    with pytest.raises(AuthorizationDenied) as exc:
        await authorize_project_action(
            db_session,
            actor_user_id=rbac.foreign_user.id,
            tenant_id=rbac.identity.alpha.tenant.id,
            project_id=rbac.identity.alpha.project.id,
            action=ACTION,
            allowed_roles=ALL_ROLES,
        )
    assert exc.value.reason is DenyReason.PROJECT_NOT_FOUND


# --------------------------------------------------------------------------
# Audit records
# --------------------------------------------------------------------------


async def test_allowed_decision_is_recorded(db_session: AsyncSession, rbac: RbacFixture):
    await _authorize(db_session, rbac, user_id=rbac.owner.id)

    decisions = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.ALLOW,
    )
    match = [d for d in decisions if d.actor_user_id == rbac.owner.id and d.action is ACTION]
    assert match
    assert match[0].project_id == rbac.identity.alpha.project.id
    assert match[0].reason is None


async def test_denied_decision_is_recorded_with_a_normalized_reason(
    db_session: AsyncSession, rbac: RbacFixture
):
    with pytest.raises(AuthorizationDenied):
        await _authorize(db_session, rbac, user_id=rbac.reviewer.id)

    decisions = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.DENY,
    )
    # Select by action rather than taking the newest: `created_at` defaults to
    # PostgreSQL now(), which is transaction-start time, so rows written in one
    # transaction share a timestamp and their relative order is arbitrary.
    match = [
        d
        for d in decisions
        if d.actor_user_id == rbac.reviewer.id and d.action is ACTION
    ]
    assert match
    assert match[0].reason == DenyReason.ROLE_NOT_PERMITTED.value


async def test_decision_metadata_records_role_and_allowed_set(
    db_session: AsyncSession, rbac: RbacFixture
):
    await _authorize(db_session, rbac, user_id=rbac.maintainer.id)

    decisions = await identity_repo.list_policy_decisions(
        db_session, tenant_id=rbac.identity.alpha.tenant.id
    )
    record = next(
        d for d in decisions if d.actor_user_id == rbac.maintainer.id and d.action is ACTION
    )
    assert record.decision_metadata["role"] == ProjectRole.MAINTAINER.value
    assert set(record.decision_metadata["allowed_roles"]) == {r.value for r in ADMIN_ROLES}


async def test_denial_for_an_unknown_project_records_no_project_id(
    db_session: AsyncSession, rbac: RbacFixture
):
    """There is no project to reference, and inventing one would corrupt the trail."""
    with pytest.raises(AuthorizationDenied):
        await _authorize(db_session, rbac, user_id=rbac.owner.id, project_id=uuid.uuid4())

    decisions = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=rbac.identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.DENY,
    )
    assert any(d.project_id is None for d in decisions)


async def test_decisions_are_written_to_the_actors_tenant(
    db_session: AsyncSession, rbac: RbacFixture
):
    """A cross-tenant attempt is recorded where it happened, not where it aimed."""
    with pytest.raises(AuthorizationDenied):
        await authorize_project_action(
            db_session,
            actor_user_id=rbac.foreign_user.id,
            tenant_id=rbac.identity.beta.tenant.id,
            project_id=rbac.identity.alpha.project.id,
            action=ACTION,
            allowed_roles=ALL_ROLES,
        )

    beta = await identity_repo.list_policy_decisions(
        db_session, tenant_id=rbac.identity.beta.tenant.id
    )
    assert any(d.actor_user_id == rbac.foreign_user.id for d in beta)


async def test_metadata_carries_no_request_detail(db_session: AsyncSession, rbac: RbacFixture):
    """Only role names and the action — never bodies, headers, or tokens."""
    await _authorize(db_session, rbac, user_id=rbac.owner.id)
    decisions = await identity_repo.list_policy_decisions(
        db_session, tenant_id=rbac.identity.alpha.tenant.id
    )
    record = next(
        d for d in decisions if d.actor_user_id == rbac.owner.id and d.action is ACTION
    )
    assert set(record.decision_metadata) == {"role", "allowed_roles"}
