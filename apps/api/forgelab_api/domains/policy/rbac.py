"""Project-scoped authorization.

Every project endpoint asks the same question: may *this actor*, in *this
tenant*, perform *this action* on *this project*? This module answers it once,
records the answer, and returns the resolved context so handlers do not repeat
the lookup.

Two design choices worth understanding before using it:

**There is no role hierarchy.** Owner is not implicitly granted whatever
Maintainer can do. A handler lists every role it accepts. Hierarchies read as
convenient and then quietly drift — someone adds a role in the middle, and
permissions shift for endpoints nobody edited. Listing roles is more verbose and
says exactly what it means. `ADMIN_ROLES` and `ALL_ROLES` exist for the common
groupings.

**A denial does not admit the project exists.** An actor who is not a member
gets the same answer as one asking about a project that was never created:
`PROJECT_NOT_FOUND`. Only a member can learn that a project exists. This is why
`no membership` and `wrong tenant` collapse into one reason rather than being
reported precisely.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import ProjectAction, ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import PolicyDecisionOutcome

#: Roles that administer a project.
ADMIN_ROLES: tuple[ProjectRole, ...] = (ProjectRole.OWNER, ProjectRole.MAINTAINER)

#: Every role. Use when membership alone is the requirement.
ALL_ROLES: tuple[ProjectRole, ...] = tuple(ProjectRole)


class DenyReason(StrEnum):
    """Why authorization failed. Normalized so audit rows stay queryable."""

    #: The project does not exist, is in another tenant, or the actor holds no
    #: active membership. Deliberately one reason — see the module docstring.
    PROJECT_NOT_FOUND = "project_not_found"

    #: The actor is a member, but their role is not accepted for this action.
    ROLE_NOT_PERMITTED = "role_not_permitted"


@dataclass(frozen=True)
class ProjectContext:
    """A resolved, authorized request. Handlers receive this instead of re-querying."""

    actor_user_id: uuid.UUID
    tenant_id: uuid.UUID
    project_id: uuid.UUID
    role: ProjectRole
    action: ProjectAction


class AuthorizationDenied(Exception):
    """Authorization failed. Carries the normalized reason."""

    def __init__(self, reason: DenyReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


async def authorize_project_action(
    session: AsyncSession,
    *,
    actor_user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    action: ProjectAction,
    allowed_roles: tuple[ProjectRole, ...],
) -> ProjectContext:
    """Authorize an action and record the decision.

    Writes a `policy_decisions` row for both outcomes — a denial nobody recorded
    is a denial nobody can investigate, and an allow-only trail cannot answer
    "who tried". The caller is responsible for committing; on denial that commit
    must still happen, or the record of the attempt is lost with the rollback.

    Raises:
        AuthorizationDenied: the actor may not perform this action here.
    """
    # Tenant scoping happens here, in the lookup — a project in another tenant
    # is simply not found, rather than found and then rejected.
    project = await identity_repo.get_project(
        session, tenant_id=tenant_id, project_id=project_id
    )
    if project is None:
        await _record(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            project_id=None,
            action=action,
            outcome=PolicyDecisionOutcome.DENY,
            reason=DenyReason.PROJECT_NOT_FOUND,
            role=None,
            allowed_roles=allowed_roles,
        )
        raise AuthorizationDenied(DenyReason.PROJECT_NOT_FOUND)

    membership = await identity_repo.get_active_membership(
        session, tenant_id=tenant_id, project_id=project_id, user_id=actor_user_id
    )
    if membership is None:
        await _record(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            project_id=project_id,
            action=action,
            outcome=PolicyDecisionOutcome.DENY,
            reason=DenyReason.PROJECT_NOT_FOUND,
            role=None,
            allowed_roles=allowed_roles,
        )
        raise AuthorizationDenied(DenyReason.PROJECT_NOT_FOUND)

    if membership.role not in allowed_roles:
        await _record(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            project_id=project_id,
            action=action,
            outcome=PolicyDecisionOutcome.DENY,
            reason=DenyReason.ROLE_NOT_PERMITTED,
            role=membership.role,
            allowed_roles=allowed_roles,
        )
        raise AuthorizationDenied(DenyReason.ROLE_NOT_PERMITTED)

    await _record(
        session,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        project_id=project_id,
        action=action,
        outcome=PolicyDecisionOutcome.ALLOW,
        reason=None,
        role=membership.role,
        allowed_roles=allowed_roles,
    )
    return ProjectContext(
        actor_user_id=actor_user_id,
        tenant_id=tenant_id,
        project_id=project_id,
        role=membership.role,
        action=action,
    )


async def _record(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    project_id: uuid.UUID | None,
    action: ProjectAction,
    outcome: PolicyDecisionOutcome,
    reason: DenyReason | None,
    role: ProjectRole | None,
    allowed_roles: tuple[ProjectRole, ...],
) -> None:
    """Persist one authorization decision.

    Metadata carries only role names and the requested action — no request
    bodies, headers, or identifiers beyond those already columns on the row.
    """
    await identity_repo.record_policy_decision(
        session,
        tenant_id=tenant_id,
        action=action,
        decision=outcome,
        actor_user_id=actor_user_id,
        project_id=project_id,
        reason=reason.value if reason else None,
        metadata={
            "role": role.value if role else None,
            "allowed_roles": [r.value for r in allowed_roles],
        },
    )
