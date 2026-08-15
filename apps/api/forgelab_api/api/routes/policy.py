"""Policy check endpoint.

Lets the dashboard ask "may I do this?" before offering a button, instead of
discovering the answer from a rejected request. The reply carries a stable code
for the client to branch on and a sentence to show the user.

Not protected by `require_project_roles`: that dependency refuses before the
handler runs, which would make it impossible to ask about an action the caller
is not permitted to take — precisely the question worth asking. Membership is
resolved inside the policy service instead, and non-membership comes back as a
`not_a_member` denial rather than an exception.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.api.dependencies import CurrentActor
from forgelab_api.core.request_context import get_request_id
from forgelab_api.db.session import get_session
from forgelab_api.domains.constants import ProjectAction
from forgelab_api.domains.policy import service as policy_service
from forgelab_api.domains.policy.rules import (
    ApprovalState,
    ChallengeState,
    DenyCode,
    GateState,
    ResourceState,
    RunState,
)

router = APIRouter(prefix="/projects/{project_id}/policy", tags=["policy"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]


class GateInput(BaseModel):
    tests_passed: int = Field(default=0, ge=0)
    tests_total: int = Field(default=0, ge=0)
    thresholds_met: bool = False


class ApprovalInput(BaseModel):
    approved: bool = False
    approver_user_id: uuid.UUID | None = None
    approver_role: str | None = None
    action: ProjectAction | None = None
    challenge_id: uuid.UUID | None = None
    revoked: bool = False


class PolicyCheckRequest(BaseModel):
    action: ProjectAction
    challenge_state: ChallengeState | None = None
    run_state: RunState | None = None
    agent_count: int | None = None
    challenge_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    gates: GateInput | None = None
    approval: ApprovalInput | None = None


class PolicyCheckResponse(BaseModel):
    permitted: bool
    action: ProjectAction
    code: DenyCode | None = None
    explanation: str


def _to_resource_state(payload: PolicyCheckRequest) -> ResourceState:
    from forgelab_api.domains.constants import ProjectRole

    approval = None
    if payload.approval is not None:
        role = None
        if payload.approval.approver_role:
            try:
                role = ProjectRole(payload.approval.approver_role)
            except ValueError:
                # An unrecognised role is treated as no role rather than
                # rejected, so approval validation refuses it on the merits.
                role = None
        approval = ApprovalState(
            approved=payload.approval.approved,
            approver_user_id=payload.approval.approver_user_id,
            approver_role=role,
            action=payload.approval.action,
            challenge_id=payload.approval.challenge_id,
            revoked=payload.approval.revoked,
        )

    gates = None
    if payload.gates is not None:
        gates = GateState(
            tests_passed=payload.gates.tests_passed,
            tests_total=payload.gates.tests_total,
            thresholds_met=payload.gates.thresholds_met,
        )

    return ResourceState(
        challenge_state=payload.challenge_state,
        run_state=payload.run_state,
        agent_count=payload.agent_count,
        gates=gates,
        approval=approval,
        challenge_id=payload.challenge_id,
        run_id=payload.run_id,
    )


@router.post("/check", response_model=PolicyCheckResponse)
async def check(
    project_id: uuid.UUID,
    payload: PolicyCheckRequest,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
) -> PolicyCheckResponse:
    """Evaluate a sensitive action without performing it.

    Always 200 for an authenticated caller — a refusal is an answer, not an
    error. The decision is persisted either way.
    """
    outcome = await policy_service.check_action(
        session,
        actor_user_id=actor.user_id,
        tenant_id=actor.tenant_id,
        project_id=project_id,
        action=payload.action,
        state=_to_resource_state(payload),
        request_id=get_request_id(request),
    )
    await session.commit()

    return PolicyCheckResponse(
        permitted=outcome.permitted,
        action=outcome.action,
        code=outcome.code,
        explanation=outcome.explanation,
    )
