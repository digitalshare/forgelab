"""Project action policy: evaluate, persist, audit.

`rules.evaluate` decides; this module resolves the actor's membership, applies
that decision, and records it twice — once as a `policy_decisions` row for
querying verdicts, and once through the audit writer for the general trail.

The double write is deliberate and required by the story. They answer different
questions: "what did we decide about pull requests on this challenge" reads the
decision table, while "what happened during that request" reads the audit
stream. Both are written here so no caller has to remember to do one of them.

Nothing is committed. The caller owns the transaction — see `docs/audit.md` for
the paths that must commit before raising.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.audit import writer as audit
from forgelab_api.domains.constants import AuditAction, AuditOutcome, ProjectAction, ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import PolicyDecisionOutcome
from forgelab_api.domains.policy.rbac import resolve_project_context
from forgelab_api.domains.policy.rules import DenyCode, ResourceState, Verdict, evaluate


@dataclass(frozen=True)
class PolicyOutcome:
    """A decision, safe to return from an API and to store."""

    permitted: bool
    action: ProjectAction
    code: DenyCode | None
    explanation: str
    actor_user_id: uuid.UUID
    tenant_id: uuid.UUID
    project_id: uuid.UUID
    role: ProjectRole | None
    challenge_id: uuid.UUID | None
    run_id: uuid.UUID | None
    decided_at: datetime


async def check_action(
    session: AsyncSession,
    *,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    action: ProjectAction,
    state: ResourceState | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> PolicyOutcome:
    """Decide whether an actor may perform an action, and record the decision.

    Never raises for a refusal — a refusal is an answer. Non-membership comes
    back as a `NOT_A_MEMBER` denial rather than an exception, so a caller can
    ask about an action it is not allowed to take and get a usable reply.
    """
    decided_at = now or datetime.now(UTC)
    resource = state or ResourceState()

    context = await resolve_project_context(
        session,
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        project_id=project_id,
        action=action,
    )

    if context is None:
        verdict = Verdict(
            permitted=False,
            code=DenyCode.NOT_A_MEMBER,
            explanation="you are not a member of this project",
        )
        role: ProjectRole | None = None
    else:
        verdict = evaluate(action=action, role=context.role, state=resource)
        role = context.role

    await _persist(
        session,
        verdict=verdict,
        action=action,
        role=role,
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        # A non-member must not have the project id echoed into their decision
        # record — the same non-disclosure rule the RBAC layer applies.
        project_id=project_id if context is not None else None,
        challenge_id=resource.challenge_id,
        run_id=resource.run_id,
        request_id=request_id,
    )

    return PolicyOutcome(
        permitted=verdict.permitted,
        action=action,
        code=verdict.code,
        explanation=verdict.explanation,
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        project_id=project_id,
        role=role,
        challenge_id=resource.challenge_id,
        run_id=resource.run_id,
        decided_at=decided_at,
    )


async def _persist(
    session: AsyncSession,
    *,
    verdict: Verdict,
    action: ProjectAction,
    role: ProjectRole | None,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID | None,
    challenge_id: uuid.UUID | None,
    run_id: uuid.UUID | None,
    request_id: str | None,
) -> None:
    """Write the decision row and the audit event."""
    outcome = (
        PolicyDecisionOutcome.ALLOW if verdict.permitted else PolicyDecisionOutcome.DENY
    )
    metadata: dict[str, object] = {
        "role": role.value if role else None,
        "code": verdict.code.value if verdict.code else None,
        **verdict.details,
    }

    await identity_repo.record_policy_decision(
        session,
        tenant_id=tenant_id,
        action=action,
        decision=outcome,
        actor_user_id=actor_user_id,
        project_id=project_id,
        challenge_id=challenge_id,
        run_id=run_id,
        # The code is what queries filter on; the sentence is for humans.
        reason=verdict.code.value if verdict.code else None,
        metadata=metadata,
    )

    await audit.record_event(
        session,
        tenant_id=tenant_id,
        action=AuditAction.POLICY_EVALUATED,
        outcome=AuditOutcome.PERMIT if verdict.permitted else AuditOutcome.DENY,
        actor_user_id=actor_user_id,
        project_id=project_id,
        challenge_id=challenge_id,
        run_id=run_id,
        request_id=request_id,
        # A permit needs no reason; a denial must carry one, and the audit
        # writer enforces that.
        reason=verdict.explanation if not verdict.permitted else None,
        metadata={"action": action.value, **metadata},
    )
