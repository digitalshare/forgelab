"""Tenant-scoped data access for identity records.

Audit events are *written* through `forgelab_api.domains.audit.writer`, not from
here — a second write path would be a way to bypass redaction and validation.
Reading them back is still this module's job.

Every read here filters on `tenant_id`, and it is a required argument rather
than something inferred from ambient state — a caller cannot forget to pass it.
Isolation is logical, not enforced by the database, so these helpers are the
boundary: query the models directly and that guarantee is gone.

Writes stay deliberately thin. Session rotation (WO-003), RBAC enforcement
(WO-008), and policy evaluation (WO-010) own their rules; this layer only
persists the results.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import ProjectAction
from forgelab_api.domains.identity.models import (
    AuditEvent,
    MembershipStatus,
    PolicyDecision,
    PolicyDecisionOutcome,
    Project,
    ProjectMembership,
    RefreshSession,
    RepositoryConnection,
    User,
)

# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


async def get_user(
    session: AsyncSession, *, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> User | None:
    result = await session.execute(
        select(User).where(User.tenant_id == tenant_id, User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_user_by_email(
    session: AsyncSession, *, tenant_id: uuid.UUID, email: str
) -> User | None:
    result = await session.execute(
        select(User).where(User.tenant_id == tenant_id, User.email == email)
    )
    return result.scalar_one_or_none()


# --------------------------------------------------------------------------
# Projects and memberships
# --------------------------------------------------------------------------


async def get_project(
    session: AsyncSession, *, tenant_id: uuid.UUID, project_id: uuid.UUID
) -> Project | None:
    result = await session.execute(
        select(Project).where(Project.tenant_id == tenant_id, Project.id == project_id)
    )
    return result.scalar_one_or_none()


async def list_projects(session: AsyncSession, *, tenant_id: uuid.UUID) -> Sequence[Project]:
    result = await session.execute(
        select(Project).where(Project.tenant_id == tenant_id).order_by(Project.name)
    )
    return result.scalars().all()


async def list_projects_for_user(
    session: AsyncSession, *, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> Sequence[Project]:
    """Projects where the user holds an active membership."""
    result = await session.execute(
        select(Project)
        .join(ProjectMembership, ProjectMembership.project_id == Project.id)
        .where(
            Project.tenant_id == tenant_id,
            ProjectMembership.tenant_id == tenant_id,
            ProjectMembership.user_id == user_id,
            ProjectMembership.status == MembershipStatus.ACTIVE,
        )
        .order_by(Project.name)
    )
    return result.scalars().all()


async def get_active_membership(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    user_id: uuid.UUID,
) -> ProjectMembership | None:
    """The user's active role on a project, or None. Basis of every RBAC check."""
    result = await session.execute(
        select(ProjectMembership).where(
            ProjectMembership.tenant_id == tenant_id,
            ProjectMembership.project_id == project_id,
            ProjectMembership.user_id == user_id,
            ProjectMembership.status == MembershipStatus.ACTIVE,
        )
    )
    return result.scalar_one_or_none()


async def list_project_members(
    session: AsyncSession, *, tenant_id: uuid.UUID, project_id: uuid.UUID
) -> Sequence[ProjectMembership]:
    result = await session.execute(
        select(ProjectMembership).where(
            ProjectMembership.tenant_id == tenant_id,
            ProjectMembership.project_id == project_id,
            ProjectMembership.status == MembershipStatus.ACTIVE,
        )
    )
    return result.scalars().all()


# --------------------------------------------------------------------------
# Repository connections
# --------------------------------------------------------------------------


async def list_repository_connections(
    session: AsyncSession, *, tenant_id: uuid.UUID, project_id: uuid.UUID
) -> Sequence[RepositoryConnection]:
    result = await session.execute(
        select(RepositoryConnection)
        .where(
            RepositoryConnection.tenant_id == tenant_id,
            RepositoryConnection.project_id == project_id,
        )
        .order_by(RepositoryConnection.full_name)
    )
    return result.scalars().all()


async def get_repository_connection(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    full_name: str,
) -> RepositoryConnection | None:
    result = await session.execute(
        select(RepositoryConnection).where(
            RepositoryConnection.tenant_id == tenant_id,
            RepositoryConnection.project_id == project_id,
            RepositoryConnection.full_name == full_name,
        )
    )
    return result.scalar_one_or_none()


# --------------------------------------------------------------------------
# Refresh sessions
# --------------------------------------------------------------------------


async def get_active_refresh_session(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    token_hash: str,
    now: datetime | None = None,
) -> RefreshSession | None:
    """Look up a live session by token hash.

    Expiry and revocation are filtered in SQL so a caller cannot accidentally
    honour a dead session by forgetting to check the columns.
    """
    moment = now or datetime.now(UTC)
    result = await session.execute(
        select(RefreshSession).where(
            RefreshSession.tenant_id == tenant_id,
            RefreshSession.token_hash == token_hash,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > moment,
        )
    )
    return result.scalar_one_or_none()


async def list_active_sessions_for_user(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    now: datetime | None = None,
) -> Sequence[RefreshSession]:
    moment = now or datetime.now(UTC)
    result = await session.execute(
        select(RefreshSession)
        .where(
            RefreshSession.tenant_id == tenant_id,
            RefreshSession.user_id == user_id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > moment,
        )
        .order_by(RefreshSession.issued_at.desc())
    )
    return result.scalars().all()


async def revoke_refresh_session(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    session_id: uuid.UUID,
    now: datetime | None = None,
) -> RefreshSession | None:
    """Mark a session revoked. Returns None if it does not belong to the tenant."""
    record = await session.get(RefreshSession, session_id)
    if record is None or record.tenant_id != tenant_id:
        return None
    record.revoked_at = now or datetime.now(UTC)
    await session.flush()
    return record


# --------------------------------------------------------------------------
# Audit events and policy decisions
# --------------------------------------------------------------------------


async def list_audit_events(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
    limit: int = 100,
) -> Sequence[AuditEvent]:
    query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    if project_id is not None:
        query = query.where(AuditEvent.project_id == project_id)
    result = await session.execute(query.order_by(AuditEvent.created_at.desc()).limit(limit))
    return result.scalars().all()


async def record_policy_decision(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: ProjectAction,
    decision: PolicyDecisionOutcome,
    actor_user_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    challenge_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyDecision:
    record = PolicyDecision(
        tenant_id=tenant_id,
        action=action,
        decision=decision,
        actor_user_id=actor_user_id,
        project_id=project_id,
        challenge_id=challenge_id,
        run_id=run_id,
        reason=reason,
        decision_metadata=metadata or {},
    )
    session.add(record)
    await session.flush()
    return record


async def list_policy_decisions(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
    decision: PolicyDecisionOutcome | None = None,
    limit: int = 100,
) -> Sequence[PolicyDecision]:
    query = select(PolicyDecision).where(PolicyDecision.tenant_id == tenant_id)
    if project_id is not None:
        query = query.where(PolicyDecision.project_id == project_id)
    if decision is not None:
        query = query.where(PolicyDecision.decision == decision)
    result = await session.execute(query.order_by(PolicyDecision.created_at.desc()).limit(limit))
    return result.scalars().all()
