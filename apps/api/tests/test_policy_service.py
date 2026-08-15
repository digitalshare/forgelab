"""Policy service and endpoint: persistence, audit, and the HTTP boundary."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import AuditAction, AuditOutcome, ProjectAction, ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import AuditEvent, PolicyDecisionOutcome, RefreshSession
from forgelab_api.domains.identity.tokens import create_access_token
from forgelab_api.domains.policy import service as policy_service
from forgelab_api.domains.policy.rules import (
    ApprovalState,
    ChallengeState,
    DenyCode,
    GateState,
    ResourceState,
)
from tests.rbac_fixtures import RbacFixture, seed_rbac_graph

CHALLENGE_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


@pytest.fixture
async def rbac(db_session: AsyncSession) -> RbacFixture:
    fixture = await seed_rbac_graph(db_session)
    await db_session.commit()
    return fixture


async def _token_for(db_session: AsyncSession, user, tenant_id: uuid.UUID) -> str:
    from datetime import UTC, datetime, timedelta

    record = RefreshSession(
        tenant_id=tenant_id,
        user_id=user.id,
        token_hash=f"policy-{uuid.uuid4().hex}",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(record)
    await db_session.flush()
    await db_session.commit()

    token, _ = create_access_token(user_id=user.id, tenant_id=tenant_id, session_id=record.id)
    return token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _check(session: AsyncSession, rbac: RbacFixture, user, action, state=None):
    return await policy_service.check_action(
        session,
        actor_user_id=user.id,
        tenant_id=rbac.identity.alpha.tenant.id,
        project_id=rbac.identity.alpha.project.id,
        action=action,
        state=state,
    )


# --------------------------------------------------------------------------
# Service behaviour
# --------------------------------------------------------------------------


async def test_permitted_action_returns_a_positive_outcome(
    db_session: AsyncSession, rbac: RbacFixture
):
    outcome = await _check(
        db_session, rbac, rbac.owner, ProjectAction.CONNECT_REPOSITORY
    )
    assert outcome.permitted
    assert outcome.code is None
    assert outcome.role is ProjectRole.OWNER


async def test_refusal_is_an_answer_not_an_exception(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Asking about an action you cannot take must return a usable reply."""
    outcome = await _check(db_session, rbac, rbac.reviewer, ProjectAction.CONNECT_REPOSITORY)
    assert not outcome.permitted
    assert outcome.code is DenyCode.ROLE_NOT_PERMITTED
    assert outcome.explanation


async def test_non_member_is_refused_without_raising(
    db_session: AsyncSession, rbac: RbacFixture
):
    outcome = await _check(db_session, rbac, rbac.non_member, ProjectAction.REVIEW_RESULT)
    assert not outcome.permitted
    assert outcome.code is DenyCode.NOT_A_MEMBER
    assert outcome.role is None


async def test_revoked_member_is_refused(db_session: AsyncSession, rbac: RbacFixture):
    outcome = await _check(db_session, rbac, rbac.revoked_member, ProjectAction.REVIEW_RESULT)
    assert outcome.code is DenyCode.NOT_A_MEMBER


async def test_cross_tenant_actor_is_refused(db_session: AsyncSession, rbac: RbacFixture):
    outcome = await policy_service.check_action(
        db_session,
        actor_user_id=rbac.foreign_user.id,
        tenant_id=rbac.identity.beta.tenant.id,
        project_id=rbac.identity.alpha.project.id,
        action=ProjectAction.REVIEW_RESULT,
    )
    assert outcome.code is DenyCode.NOT_A_MEMBER


# --------------------------------------------------------------------------
# Persistence: decision row and audit event
# --------------------------------------------------------------------------


async def _decisions(session: AsyncSession, rbac: RbacFixture, actor_id: uuid.UUID):
    rows = await identity_repo.list_policy_decisions(
        session, tenant_id=rbac.identity.alpha.tenant.id
    )
    return [d for d in rows if d.actor_user_id == actor_id]


async def _policy_audit(session: AsyncSession, rbac: RbacFixture) -> list[AuditEvent]:
    result = await session.execute(
        select(AuditEvent).where(
            AuditEvent.tenant_id == rbac.identity.alpha.tenant.id,
            AuditEvent.action == AuditAction.POLICY_EVALUATED,
        )
    )
    return list(result.scalars().all())


async def test_a_permit_is_persisted_as_a_decision(
    db_session: AsyncSession, rbac: RbacFixture
):
    await _check(db_session, rbac, rbac.maintainer, ProjectAction.CONNECT_REPOSITORY)
    rows = await _decisions(db_session, rbac, rbac.maintainer.id)
    assert any(d.decision is PolicyDecisionOutcome.ALLOW for d in rows)


async def test_a_denial_persists_its_reason_code(db_session: AsyncSession, rbac: RbacFixture):
    """The code is what queries filter on; the sentence is for humans."""
    await _check(db_session, rbac, rbac.operator, ProjectAction.APPROVE_RESULT)
    rows = await _decisions(db_session, rbac, rbac.operator.id)
    denials = [d for d in rows if d.decision is PolicyDecisionOutcome.DENY]
    assert denials
    assert denials[0].reason == DenyCode.ROLE_NOT_PERMITTED.value


async def test_every_decision_also_emits_an_audit_event(
    db_session: AsyncSession, rbac: RbacFixture
):
    await _check(db_session, rbac, rbac.owner, ProjectAction.CONNECT_REPOSITORY)
    events = await _policy_audit(db_session, rbac)
    assert events
    assert events[0].outcome is AuditOutcome.PERMIT
    assert events[0].event_metadata["action"] == ProjectAction.CONNECT_REPOSITORY.value


async def test_denial_audit_event_carries_an_explanation(
    db_session: AsyncSession, rbac: RbacFixture
):
    await _check(db_session, rbac, rbac.reviewer, ProjectAction.CONNECT_REPOSITORY)
    denials = [e for e in await _policy_audit(db_session, rbac) if e.outcome is AuditOutcome.DENY]
    assert denials
    assert denials[0].reason


async def test_non_member_decision_does_not_echo_the_project_id(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Same non-disclosure rule the RBAC layer applies."""
    await _check(db_session, rbac, rbac.non_member, ProjectAction.REVIEW_RESULT)
    rows = await _decisions(db_session, rbac, rbac.non_member.id)
    assert rows
    assert all(d.project_id is None for d in rows)


async def test_challenge_and_run_identifiers_are_recorded(
    db_session: AsyncSession, rbac: RbacFixture
):
    run_id = uuid.uuid4()
    await _check(
        db_session,
        rbac,
        rbac.operator,
        ProjectAction.RERUN_FAILED_AGENT,
        ResourceState(run_state=None, challenge_id=CHALLENGE_ID, run_id=run_id),
    )
    rows = await _decisions(db_session, rbac, rbac.operator.id)
    assert any(d.challenge_id == CHALLENGE_ID and d.run_id == run_id for d in rows)


async def test_decision_metadata_carries_no_credentials(
    db_session: AsyncSession, rbac: RbacFixture
):
    await _check(db_session, rbac, rbac.owner, ProjectAction.CONNECT_REPOSITORY)
    for event in await _policy_audit(db_session, rbac):
        assert "token" not in str(event.event_metadata).lower()


async def test_policy_evaluated_action_is_accepted_by_the_database(
    db_session: AsyncSession, rbac: RbacFixture
):
    """Guards the CHECK constraint migration for the new audit action."""
    await _check(db_session, rbac, rbac.owner, ProjectAction.REVIEW_RESULT)
    await db_session.flush()
    assert await _policy_audit(db_session, rbac)


# --------------------------------------------------------------------------
# The gated pull-request path, end to end through the service
# --------------------------------------------------------------------------


async def test_pull_request_denied_when_gates_fail(db_session: AsyncSession, rbac: RbacFixture):
    outcome = await _check(
        db_session,
        rbac,
        rbac.owner,
        ProjectAction.CREATE_PULL_REQUEST,
        ResourceState(
            challenge_state=ChallengeState.COMPLETE,
            challenge_id=CHALLENGE_ID,
            gates=GateState(tests_passed=10, tests_total=15, thresholds_met=False),
        ),
    )
    assert outcome.code is DenyCode.APPROVAL_REQUIRED


async def test_pull_request_allowed_with_a_valid_approval(
    db_session: AsyncSession, rbac: RbacFixture
):
    outcome = await _check(
        db_session,
        rbac,
        rbac.owner,
        ProjectAction.CREATE_PULL_REQUEST,
        ResourceState(
            challenge_state=ChallengeState.COMPLETE,
            challenge_id=CHALLENGE_ID,
            gates=GateState(tests_passed=10, tests_total=15, thresholds_met=False),
            approval=ApprovalState(
                approved=True,
                approver_role=ProjectRole.REVIEWER,
                action=ProjectAction.CREATE_PULL_REQUEST,
                challenge_id=CHALLENGE_ID,
            ),
        ),
    )
    assert outcome.permitted


# --------------------------------------------------------------------------
# HTTP boundary
# --------------------------------------------------------------------------


async def test_endpoint_requires_authentication(rbac_client: AsyncClient, rbac: RbacFixture):
    response = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "launch_challenge"},
    )
    assert response.status_code == 401


async def test_endpoint_returns_a_permit(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "connect_repository"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    assert response.json()["permitted"] is True


async def test_endpoint_returns_200_for_a_refusal(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    """A refusal is an answer, not an error — the caller asked a question."""
    token = await _token_for(db_session, rbac.reviewer, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "connect_repository"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["permitted"] is False
    assert body["code"] == DenyCode.ROLE_NOT_PERMITTED.value
    assert body["explanation"]


async def test_endpoint_evaluates_the_gated_pull_request_path(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    payload = {
        "action": "create_pull_request",
        "challenge_state": "complete",
        "challenge_id": str(CHALLENGE_ID),
        "gates": {"tests_passed": 12, "tests_total": 15, "thresholds_met": False},
    }

    denied = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json=payload,
        headers=_auth(token),
    )
    assert denied.json()["code"] == DenyCode.APPROVAL_REQUIRED.value

    payload["approval"] = {
        "approved": True,
        "approver_role": "reviewer",
        "action": "create_pull_request",
        "challenge_id": str(CHALLENGE_ID),
    }
    allowed = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json=payload,
        headers=_auth(token),
    )
    assert allowed.json()["permitted"] is True


async def test_endpoint_refuses_a_non_member(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.non_member, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "review_result"},
        headers=_auth(token),
    )
    assert response.json()["code"] == DenyCode.NOT_A_MEMBER.value


async def test_endpoint_rejects_an_unknown_action(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    response = await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "delete_everything"},
        headers=_auth(token),
    )
    assert response.status_code == 422


async def test_endpoint_persists_the_decision(
    rbac_client: AsyncClient, db_session: AsyncSession, rbac: RbacFixture
):
    token = await _token_for(db_session, rbac.owner, rbac.identity.alpha.tenant.id)
    await rbac_client.post(
        f"/projects/{rbac.identity.alpha.project.id}/policy/check",
        json={"action": "connect_repository"},
        headers=_auth(token),
    )
    assert await _policy_audit(db_session, rbac)
    assert await _decisions(db_session, rbac, rbac.owner.id)
