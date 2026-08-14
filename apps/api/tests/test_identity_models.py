"""Structural tests for the identity models — schema definition, no database."""

from __future__ import annotations

from sqlalchemy import CheckConstraint, Index, UniqueConstraint

from forgelab_api.db.base import Base
from forgelab_api.domains.constants import ProjectRole
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

IDENTITY_TABLES = {
    "tenants",
    "users",
    "projects",
    "project_memberships",
    "repository_connections",
    "refresh_sessions",
    "audit_events",
    "policy_decisions",
}

TENANT_SCOPED_MODELS = [
    User,
    Project,
    ProjectMembership,
    RepositoryConnection,
    RefreshSession,
    AuditEvent,
    PolicyDecision,
]


def test_every_identity_table_is_registered():
    assert IDENTITY_TABLES <= set(Base.metadata.tables)


def test_tenant_table_is_not_itself_tenant_scoped():
    """`tenants` is the isolation root; a tenant_id column on it would be circular."""
    assert "tenant_id" not in Tenant.__table__.columns


def test_every_other_table_carries_an_indexed_tenant_id():
    for model in TENANT_SCOPED_MODELS:
        column = model.__table__.columns.get("tenant_id")
        assert column is not None, f"{model.__tablename__} is missing tenant_id"
        assert not column.nullable, f"{model.__tablename__}.tenant_id must be NOT NULL"
        indexed = any(
            "tenant_id" in [c.name for c in index.columns] for index in model.__table__.indexes
        )
        assert indexed, f"{model.__tablename__}.tenant_id is not indexed"


def test_tenant_foreign_keys_cascade():
    """Deleting a tenant must not strand rows behind it."""
    for model in TENANT_SCOPED_MODELS:
        fk = next(iter(model.__table__.columns["tenant_id"].foreign_keys))
        assert fk.column.table.name == "tenants"
        assert fk.ondelete == "CASCADE"


def test_user_email_is_unique_per_tenant_not_globally():
    constraint = next(
        c for c in User.__table__.constraints if isinstance(c, UniqueConstraint)
    )
    assert [c.name for c in constraint.columns] == ["tenant_id", "email"]


def test_project_slug_is_unique_per_tenant():
    constraint = next(
        c for c in Project.__table__.constraints if isinstance(c, UniqueConstraint)
    )
    assert [c.name for c in constraint.columns] == ["tenant_id", "slug"]


def test_active_membership_uniqueness_is_a_partial_index():
    """A plain unique constraint would block re-granting access after revocation."""
    index = next(
        i for i in ProjectMembership.__table__.indexes if i.name == "uq_project_memberships_active"
    )
    assert index.unique
    assert {c.name for c in index.columns} == {"project_id", "user_id"}
    where = str(index.dialect_options["postgresql"]["where"])
    assert "active" in where


def test_repository_is_unique_per_project():
    constraint = next(
        c for c in RepositoryConnection.__table__.constraints if isinstance(c, UniqueConstraint)
    )
    assert [c.name for c in constraint.columns] == ["project_id", "full_name"]


def test_refresh_session_stores_only_a_hash_and_is_unique():
    columns = RefreshSession.__table__.columns
    assert columns["token_hash"].unique
    assert "token" not in columns, "raw refresh tokens must never be persisted"


def test_enum_columns_have_database_check_constraints():
    """The Python enum only guards ORM writes; the CHECK also covers raw SQL."""
    checked = {
        (ProjectMembership, "role", ProjectRole),
        (ProjectMembership, "status", MembershipStatus),
        (PolicyDecision, "decision", PolicyDecisionOutcome),
    }
    for model, column_name, enum_cls in checked:
        column = model.__table__.columns[column_name]
        constraints = [c for c in column.table.constraints if isinstance(c, CheckConstraint)]
        assert any(column_name in str(c.sqltext) for c in constraints), (
            f"{model.__tablename__}.{column_name} has no CHECK constraint"
        )
        assert set(column.type.enums) == {member.value for member in enum_cls}


def test_audit_and_policy_tables_are_append_only():
    """No updated_at — these rows are written once and never edited."""
    for model in (AuditEvent, PolicyDecision):
        assert "created_at" in model.__table__.columns
        assert "updated_at" not in model.__table__.columns


def test_audit_actor_is_nullable_for_system_events():
    """Sandbox cleanup and reconciliation have no human actor."""
    assert AuditEvent.__table__.columns["actor_user_id"].nullable
    assert PolicyDecision.__table__.columns["actor_user_id"].nullable


def test_challenge_and_run_columns_have_no_foreign_keys_yet():
    """challenges and agent_runs arrive with WO-007/WO-012; FKs come with them."""
    for model in (AuditEvent, PolicyDecision):
        for column_name in ("challenge_id", "run_id"):
            assert not model.__table__.columns[column_name].foreign_keys


def test_dashboard_query_indexes_exist():
    audit_indexes = {i.name for i in AuditEvent.__table__.indexes}
    assert "ix_audit_events_tenant_created" in audit_indexes
    assert "ix_audit_events_project_created" in audit_indexes
    assert any(isinstance(i, Index) for i in AuditEvent.__table__.indexes)
