"""Database integration tests for identity persistence.

These run against a real PostgreSQL database built from the Alembic migrations.
The central concern is tenant isolation: every helper is asserted to withhold
another tenant's rows, using a fixture where those rows genuinely exist.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import AuditAction, ProjectAction, ProjectRole
from forgelab_api.domains.identity import repository as identity_repo
from forgelab_api.domains.identity.models import (
    AuditEvent,
    MembershipStatus,
    PolicyDecisionOutcome,
    Project,
    ProjectMembership,
    RefreshSession,
    RepositoryConnection,
    Tenant,
    User,
)
from tests.identity_fixtures import IdentityFixture, seed_identity_graph


@pytest.fixture
async def identity(db_session: AsyncSession) -> IdentityFixture:
    return await seed_identity_graph(db_session)


# --------------------------------------------------------------------------
# Migration state
# --------------------------------------------------------------------------


async def test_migrations_created_every_identity_table(db_session: AsyncSession):
    result = await db_session.execute(
        text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    )
    tables = {row[0] for row in result}
    assert {
        "tenants",
        "users",
        "projects",
        "project_memberships",
        "repository_connections",
        "refresh_sessions",
        "audit_events",
        "policy_decisions",
    } <= tables


async def test_migration_is_at_head(db_session: AsyncSession):
    result = await db_session.execute(text("SELECT version_num FROM alembic_version"))
    assert result.scalar_one()


# --------------------------------------------------------------------------
# Cross-tenant isolation
# --------------------------------------------------------------------------


async def test_project_lookup_withholds_another_tenants_project(
    db_session: AsyncSession, identity: IdentityFixture
):
    """The row exists — it just must not be reachable through the wrong tenant."""
    found = await identity_repo.get_project(
        db_session, tenant_id=identity.alpha.tenant.id, project_id=identity.beta.project.id
    )
    assert found is None

    direct = await db_session.get(Project, identity.beta.project.id)
    assert direct is not None, "fixture must actually contain the other tenant's project"


async def test_project_listing_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    alpha_projects = await identity_repo.list_projects(
        db_session, tenant_id=identity.alpha.tenant.id
    )
    assert [p.id for p in alpha_projects] == [identity.alpha.project.id]


async def test_user_lookup_by_email_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    beta_email = identity.beta.owner.email
    assert (
        await identity_repo.get_user_by_email(
            db_session, tenant_id=identity.alpha.tenant.id, email=beta_email
        )
        is None
    )
    assert (
        await identity_repo.get_user_by_email(
            db_session, tenant_id=identity.beta.tenant.id, email=beta_email
        )
    ) is not None


async def test_membership_lookup_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    membership = await identity_repo.get_active_membership(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        project_id=identity.beta.project.id,
        user_id=identity.beta.owner.id,
    )
    assert membership is None


async def test_repository_listing_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    connections = await identity_repo.list_repository_connections(
        db_session, tenant_id=identity.alpha.tenant.id, project_id=identity.beta.project.id
    )
    assert list(connections) == []


async def test_audit_listing_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    events = await identity_repo.list_audit_events(
        db_session, tenant_id=identity.alpha.tenant.id
    )
    assert {e.tenant_id for e in events} == {identity.alpha.tenant.id}


async def test_policy_decision_listing_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    decisions = await identity_repo.list_policy_decisions(
        db_session, tenant_id=identity.beta.tenant.id
    )
    assert {d.tenant_id for d in decisions} == {identity.beta.tenant.id}


async def test_refresh_session_lookup_is_tenant_scoped(
    db_session: AsyncSession, identity: IdentityFixture
):
    """A stolen token hash must not authenticate against a different tenant."""
    assert (
        await identity_repo.get_active_refresh_session(
            db_session,
            tenant_id=identity.alpha.tenant.id,
            token_hash=identity.beta.session.token_hash,
        )
        is None
    )


async def test_revoking_another_tenants_session_is_refused(
    db_session: AsyncSession, identity: IdentityFixture
):
    result = await identity_repo.revoke_refresh_session(
        db_session, tenant_id=identity.alpha.tenant.id, session_id=identity.beta.session.id
    )
    assert result is None
    assert identity.beta.session.revoked_at is None


# --------------------------------------------------------------------------
# Constraints
# --------------------------------------------------------------------------


async def test_duplicate_active_membership_is_rejected(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        ProjectMembership(
            tenant_id=identity.alpha.tenant.id,
            project_id=identity.alpha.project.id,
            user_id=identity.alpha.owner.id,
            role=ProjectRole.MAINTAINER,
            status=MembershipStatus.ACTIVE,
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_membership_can_be_regranted_after_revocation(
    db_session: AsyncSession, identity: IdentityFixture
):
    """The partial index exists precisely so this works."""
    identity.alpha.owner_membership.status = MembershipStatus.REVOKED
    await db_session.flush()

    db_session.add(
        ProjectMembership(
            tenant_id=identity.alpha.tenant.id,
            project_id=identity.alpha.project.id,
            user_id=identity.alpha.owner.id,
            role=ProjectRole.MAINTAINER,
            status=MembershipStatus.ACTIVE,
        )
    )
    await db_session.flush()

    active = await identity_repo.get_active_membership(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        project_id=identity.alpha.project.id,
        user_id=identity.alpha.owner.id,
    )
    assert active is not None
    assert active.role is ProjectRole.MAINTAINER


async def test_same_email_may_exist_in_two_tenants(
    db_session: AsyncSession, identity: IdentityFixture
):
    shared = "person@example.com"
    db_session.add(User(tenant_id=identity.alpha.tenant.id, email=shared, display_name="A"))
    db_session.add(User(tenant_id=identity.beta.tenant.id, email=shared, display_name="B"))
    await db_session.flush()

    result = await db_session.execute(
        select(func.count()).select_from(User).where(User.email == shared)
    )
    assert result.scalar_one() == 2


async def test_duplicate_email_within_one_tenant_is_rejected(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        User(
            tenant_id=identity.alpha.tenant.id,
            email=identity.alpha.owner.email,
            display_name="Impostor",
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_duplicate_repository_per_project_is_rejected(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        RepositoryConnection(
            tenant_id=identity.alpha.tenant.id,
            project_id=identity.alpha.project.id,
            full_name=identity.alpha.repository.full_name,
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_duplicate_token_hash_is_rejected(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        RefreshSession(
            tenant_id=identity.beta.tenant.id,
            user_id=identity.beta.owner.id,
            token_hash=identity.alpha.session.token_hash,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_invalid_role_is_rejected_by_the_database(
    db_session: AsyncSession, identity: IdentityFixture
):
    """Raw SQL bypasses the Python enum — the CHECK constraint must still hold."""
    with pytest.raises(DBAPIError):
        await db_session.execute(
            text(
                "INSERT INTO project_memberships "
                "(id, tenant_id, project_id, user_id, role, status, created_at, updated_at) "
                "VALUES (:id, :tenant, :project, :user, 'superadmin', 'active', now(), now())"
            ),
            {
                "id": uuid.uuid4(),
                "tenant": identity.alpha.tenant.id,
                "project": identity.alpha.project.id,
                "user": identity.alpha.reviewer.id,
            },
        )


async def test_membership_requires_a_real_user(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        ProjectMembership(
            tenant_id=identity.alpha.tenant.id,
            project_id=identity.alpha.project.id,
            user_id=uuid.uuid4(),
            role=ProjectRole.OPERATOR,
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_deleting_a_tenant_cascades_to_its_records(
    db_session: AsyncSession, identity: IdentityFixture
):
    tenant_id = identity.alpha.tenant.id
    await db_session.delete(await db_session.get(Tenant, tenant_id))
    await db_session.flush()

    for model in (User, Project, ProjectMembership, RepositoryConnection, RefreshSession):
        result = await db_session.execute(
            select(func.count()).select_from(model).where(model.tenant_id == tenant_id)
        )
        assert result.scalar_one() == 0, f"{model.__tablename__} rows survived tenant deletion"

    surviving = await db_session.execute(
        select(func.count())
        .select_from(Project)
        .where(Project.tenant_id == identity.beta.tenant.id)
    )
    assert surviving.scalar_one() == 1


# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------


async def test_expired_session_is_not_returned(
    db_session: AsyncSession, identity: IdentityFixture
):
    expired = RefreshSession(
        tenant_id=identity.alpha.tenant.id,
        user_id=identity.alpha.owner.id,
        token_hash=f"expired-{uuid.uuid4().hex}",
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    db_session.add(expired)
    await db_session.flush()

    assert (
        await identity_repo.get_active_refresh_session(
            db_session, tenant_id=identity.alpha.tenant.id, token_hash=expired.token_hash
        )
        is None
    )


async def test_revoked_session_is_not_returned(
    db_session: AsyncSession, identity: IdentityFixture
):
    revoked = await identity_repo.revoke_refresh_session(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        session_id=identity.alpha.session.id,
    )
    assert revoked is not None and revoked.revoked_at is not None

    assert (
        await identity_repo.get_active_refresh_session(
            db_session,
            tenant_id=identity.alpha.tenant.id,
            token_hash=identity.alpha.session.token_hash,
        )
        is None
    )


async def test_active_session_is_returned_for_its_own_tenant(
    db_session: AsyncSession, identity: IdentityFixture
):
    found = await identity_repo.get_active_refresh_session(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        token_hash=identity.alpha.session.token_hash,
    )
    assert found is not None
    assert found.id == identity.alpha.session.id


async def test_listing_active_sessions_excludes_dead_ones(
    db_session: AsyncSession, identity: IdentityFixture
):
    db_session.add(
        RefreshSession(
            tenant_id=identity.alpha.tenant.id,
            user_id=identity.alpha.owner.id,
            token_hash=f"dead-{uuid.uuid4().hex}",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    await db_session.flush()

    sessions = await identity_repo.list_active_sessions_for_user(
        db_session, tenant_id=identity.alpha.tenant.id, user_id=identity.alpha.owner.id
    )
    assert [s.id for s in sessions] == [identity.alpha.session.id]


# --------------------------------------------------------------------------
# Membership and project queries
# --------------------------------------------------------------------------


async def test_projects_for_user_returns_only_active_memberships(
    db_session: AsyncSession, identity: IdentityFixture
):
    projects = await identity_repo.list_projects_for_user(
        db_session, tenant_id=identity.alpha.tenant.id, user_id=identity.alpha.reviewer.id
    )
    assert [p.id for p in projects] == [identity.alpha.project.id]

    identity.alpha.reviewer_membership.status = MembershipStatus.REVOKED
    await db_session.flush()

    after = await identity_repo.list_projects_for_user(
        db_session, tenant_id=identity.alpha.tenant.id, user_id=identity.alpha.reviewer.id
    )
    assert list(after) == []


async def test_project_members_excludes_revoked(
    db_session: AsyncSession, identity: IdentityFixture
):
    identity.alpha.reviewer_membership.status = MembershipStatus.REVOKED
    await db_session.flush()

    members = await identity_repo.list_project_members(
        db_session, tenant_id=identity.alpha.tenant.id, project_id=identity.alpha.project.id
    )
    assert [m.user_id for m in members] == [identity.alpha.owner.id]


async def test_repository_connection_round_trips_its_language(
    db_session: AsyncSession, identity: IdentityFixture
):
    found = await identity_repo.get_repository_connection(
        db_session,
        tenant_id=identity.beta.tenant.id,
        project_id=identity.beta.project.id,
        full_name=identity.beta.repository.full_name,
    )
    assert found is not None
    assert found.language is not None
    assert found.language.value == "nodejs"
    assert found.installation_id == "install-beta"


# --------------------------------------------------------------------------
# Audit and policy writes
# --------------------------------------------------------------------------


async def test_audit_event_round_trips_with_metadata(
    db_session: AsyncSession, identity: IdentityFixture
):
    run_id = uuid.uuid4()
    event = await identity_repo.record_audit_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.CHALLENGE_LAUNCHED,
        actor_user_id=identity.alpha.owner.id,
        project_id=identity.alpha.project.id,
        run_id=run_id,
        metadata={"agents": 3},
    )
    assert event.id is not None

    stored = await db_session.get(AuditEvent, event.id)
    assert stored is not None
    assert stored.action is AuditAction.CHALLENGE_LAUNCHED
    assert stored.event_metadata == {"agents": 3}
    assert stored.run_id == run_id
    assert stored.created_at is not None


async def test_system_audit_event_needs_no_actor(
    db_session: AsyncSession, identity: IdentityFixture
):
    event = await identity_repo.record_audit_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.SANDBOX_DESTROYED,
        metadata={"reason": "ttl"},
    )
    assert event.actor_user_id is None


async def test_policy_decision_records_a_denial_with_reason(
    db_session: AsyncSession, identity: IdentityFixture
):
    decision = await identity_repo.record_policy_decision(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=ProjectAction.CREATE_PULL_REQUEST,
        decision=PolicyDecisionOutcome.DENY,
        actor_user_id=identity.alpha.reviewer.id,
        project_id=identity.alpha.project.id,
        reason="score below threshold",
    )
    assert decision.decision is PolicyDecisionOutcome.DENY

    denials = await identity_repo.list_policy_decisions(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        decision=PolicyDecisionOutcome.DENY,
    )
    assert decision.id in {d.id for d in denials}


async def test_audit_listing_can_narrow_to_one_project(
    db_session: AsyncSession, identity: IdentityFixture
):
    await identity_repo.record_audit_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.CREDENTIAL_ISSUED,
        project_id=None,
    )
    scoped = await identity_repo.list_audit_events(
        db_session, tenant_id=identity.alpha.tenant.id, project_id=identity.alpha.project.id
    )
    assert all(e.project_id == identity.alpha.project.id for e in scoped)
