"""Database fixtures for identity tests.

Seeds two fully populated tenants. The second tenant is not decoration — it is
what makes cross-tenant isolation testable. A helper that forgets its
`tenant_id` filter passes happily against a single-tenant fixture and leaks in
production, so every isolation assertion here compares tenant A's results
against rows that genuinely exist under tenant B.

No credentials: refresh sessions store a fake hash, and repository connections
store an installation id, never a token.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import (
    AuditAction,
    ProjectAction,
    ProjectRole,
    SupportedLanguage,
)
from forgelab_api.domains.identity.models import (
    AuditEvent,
    MembershipStatus,
    PolicyDecision,
    PolicyDecisionOutcome,
    Project,
    ProjectMembership,
    RefreshSession,
    RepositoryConnection,
    Tenant,
    User,
)


@dataclass
class TenantGraph:
    """One tenant and everything hanging off it."""

    tenant: Tenant
    owner: User
    reviewer: User
    project: Project
    owner_membership: ProjectMembership
    reviewer_membership: ProjectMembership
    repository: RepositoryConnection
    session: RefreshSession
    audit_event: AuditEvent
    policy_decision: PolicyDecision


@dataclass
class IdentityFixture:
    """Two independent tenants, each fully populated."""

    alpha: TenantGraph
    beta: TenantGraph


async def _seed_tenant(
    session: AsyncSession,
    *,
    slug: str,
    name: str,
    repo_full_name: str,
    language: SupportedLanguage,
) -> TenantGraph:
    tenant = Tenant(name=name, slug=slug)
    session.add(tenant)
    await session.flush()

    owner = User(
        tenant_id=tenant.id,
        email=f"owner@{slug}.example",
        display_name=f"{name} Owner",
    )
    reviewer = User(
        tenant_id=tenant.id,
        email=f"reviewer@{slug}.example",
        display_name=f"{name} Reviewer",
    )
    project = Project(tenant_id=tenant.id, name=f"{name} Platform", slug=f"{slug}-platform")
    session.add_all([owner, reviewer, project])
    await session.flush()

    owner_membership = ProjectMembership(
        tenant_id=tenant.id,
        project_id=project.id,
        user_id=owner.id,
        role=ProjectRole.OWNER,
        status=MembershipStatus.ACTIVE,
    )
    reviewer_membership = ProjectMembership(
        tenant_id=tenant.id,
        project_id=project.id,
        user_id=reviewer.id,
        role=ProjectRole.REVIEWER,
        status=MembershipStatus.ACTIVE,
    )
    repository = RepositoryConnection(
        tenant_id=tenant.id,
        project_id=project.id,
        full_name=repo_full_name,
        installation_id=f"install-{slug}",
        language=language,
    )
    refresh_session = RefreshSession(
        tenant_id=tenant.id,
        user_id=owner.id,
        token_hash=f"hash-{slug}-{uuid.uuid4().hex}",
        expires_at=datetime.now(UTC) + timedelta(hours=12),
        user_agent="pytest",
        ip_address="127.0.0.1",
    )
    audit_event = AuditEvent(
        tenant_id=tenant.id,
        actor_user_id=owner.id,
        project_id=project.id,
        action=AuditAction.REPOSITORY_CONNECTED,
        event_metadata={"repository": repo_full_name},
    )
    policy_decision = PolicyDecision(
        tenant_id=tenant.id,
        actor_user_id=reviewer.id,
        project_id=project.id,
        action=ProjectAction.CREATE_PULL_REQUEST,
        decision=PolicyDecisionOutcome.DENY,
        reason="reviewer may not open pull requests",
        decision_metadata={"role": ProjectRole.REVIEWER.value},
    )
    session.add_all(
        [
            owner_membership,
            reviewer_membership,
            repository,
            refresh_session,
            audit_event,
            policy_decision,
        ]
    )
    await session.flush()

    return TenantGraph(
        tenant=tenant,
        owner=owner,
        reviewer=reviewer,
        project=project,
        owner_membership=owner_membership,
        reviewer_membership=reviewer_membership,
        repository=repository,
        session=refresh_session,
        audit_event=audit_event,
        policy_decision=policy_decision,
    )


async def seed_identity_graph(session: AsyncSession) -> IdentityFixture:
    """Populate two tenants with a matching shape so isolation is comparable."""
    alpha = await _seed_tenant(
        session,
        slug="alpha",
        name="Alpha Industries",
        repo_full_name="alpha/checkout-service",
        language=SupportedLanguage.PYTHON,
    )
    beta = await _seed_tenant(
        session,
        slug="beta",
        name="Beta Works",
        repo_full_name="beta/billing-service",
        language=SupportedLanguage.NODEJS,
    )
    return IdentityFixture(alpha=alpha, beta=beta)
