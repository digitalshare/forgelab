"""Multi-tenant identity persistence models.

Isolation is logical: every table below carries `tenant_id`, and the repository
helpers in this package filter on it for every read. Nothing here enforces
isolation at the database level, so callers must go through those helpers rather
than querying the models directly.

Two deliberate choices:

* **No ORM relationships.** Under async SQLAlchemy a lazy-loaded relationship
  raises `MissingGreenlet` at attribute access, which turns a modelling
  convenience into a runtime failure far from its cause. Joins are written
  explicitly in the repository layer instead.
* **Enums are stored as constrained strings** (`native_enum=False`), not
  PostgreSQL enum types. Adding a value to a native enum requires `ALTER TYPE`
  and cannot run inside a transactional migration on older servers; a CHECK
  constraint is edited like any other column.

`challenge_id` and `run_id` on the audit and policy tables are plain UUID
columns without foreign keys — the `challenges` and `agent_runs` tables arrive
with WO-007 and WO-012. The constraints should be added when those land.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from forgelab_api.db.base import (
    Base,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    enum_column,
)
from forgelab_api.domains.constants import (
    AuditAction,
    AuditOutcome,
    ProjectAction,
    ProjectRole,
    SupportedLanguage,
)


class MembershipStatus(StrEnum):
    """Lifecycle of a user's membership in a project."""

    ACTIVE = "active"
    REVOKED = "revoked"


class RepositoryConnectionStatus(StrEnum):
    """Lifecycle of a project's link to an external repository."""

    PENDING = "pending"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class PolicyDecisionOutcome(StrEnum):
    """Result of evaluating a project action against policy."""

    ALLOW = "allow"
    DENY = "deny"


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Top-level isolation boundary. Every other table hangs off this."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)


class User(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A person within one tenant.

    Email is unique per tenant rather than globally — the same address may belong
    to separate people in unrelated tenants.
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
        Index("ix_users_tenant_active", "tenant_id", "is_active"),
    )

    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Project(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A unit of work owned by a tenant; challenges and repositories hang off it."""

    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("tenant_id", "slug", name="uq_projects_tenant_slug"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)


class ProjectMembership(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """Grants a user one role on one project.

    A user may hold at most one *active* membership per project, enforced by a
    partial unique index. Revoked rows are retained for audit, so a plain unique
    constraint would block re-granting access after a revocation.
    """

    __tablename__ = "project_memberships"
    __table_args__ = (
        Index(
            "uq_project_memberships_active",
            "project_id",
            "user_id",
            unique=True,
            postgresql_where=text(f"status = '{MembershipStatus.ACTIVE.value}'"),
        ),
        Index("ix_project_memberships_user", "tenant_id", "user_id"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[ProjectRole] = mapped_column(
        enum_column(ProjectRole, "project_role"), nullable=False
    )
    status: Mapped[MembershipStatus] = mapped_column(
        enum_column(MembershipStatus, "membership_status"),
        nullable=False,
        default=MembershipStatus.ACTIVE,
    )


class RepositoryConnection(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A project's link to an external repository.

    Only the installation identifier is stored — never a token. Short-lived
    credentials are minted on demand by the broker (WO-022).
    """

    __tablename__ = "repository_connections"
    __table_args__ = (
        UniqueConstraint("project_id", "full_name", name="uq_repository_connections_project_name"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="github")
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    installation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    language: Mapped[SupportedLanguage | None] = mapped_column(
        enum_column(SupportedLanguage, "supported_language"), nullable=True
    )
    status: Mapped[RepositoryConnectionStatus] = mapped_column(
        enum_column(RepositoryConnectionStatus, "repository_connection_status"),
        nullable=False,
        default=RepositoryConnectionStatus.PENDING,
    )


class RefreshSession(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """Server-side state for one refresh token.

    Only a hash of the token is persisted, so a database disclosure does not
    yield usable credentials. Rotation is implemented in WO-003; this table
    provides the durable state it rotates.
    """

    __tablename__ = "refresh_sessions"
    __table_args__ = (Index("ix_refresh_sessions_user_expiry", "user_id", "expires_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)


class AuditEvent(UUIDPrimaryKeyMixin, TenantScopedMixin, Base):
    """An immutable record of something that happened.

    No `updated_at`: audit rows are append-only. `actor_user_id` is nullable so
    system-initiated events (sandbox cleanup, reconciliation) can be recorded
    without inventing a user.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_tenant_created", "tenant_id", "created_at"),
        Index("ix_audit_events_project_created", "project_id", "created_at"),
        Index("ix_audit_events_run", "run_id"),
        Index("ix_audit_events_request", "request_id"),
        Index("ix_audit_events_action_outcome", "action", "outcome"),
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    challenge_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    action: Mapped[AuditAction] = mapped_column(
        enum_column(AuditAction, "audit_action"), nullable=False
    )
    #: Normalized outcome. Nullable only so rows written before WO-006 remain
    #: valid; every new write sets it.
    outcome: Mapped[AuditOutcome | None] = mapped_column(
        enum_column(AuditOutcome, "audit_outcome"), nullable=True
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Correlates every event emitted while handling one request.
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class PolicyDecision(UUIDPrimaryKeyMixin, TenantScopedMixin, Base):
    """A persisted allow/deny decision for a sensitive project action.

    Append-only like `audit_events`. Kept separate because a decision carries a
    verdict and a reason, and because denials are the interesting rows — mixing
    them into the audit stream would bury them.
    """

    __tablename__ = "policy_decisions"
    __table_args__ = (
        Index("ix_policy_decisions_tenant_created", "tenant_id", "created_at"),
        Index("ix_policy_decisions_project_action", "project_id", "action"),
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    challenge_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    action: Mapped[ProjectAction] = mapped_column(
        enum_column(ProjectAction, "project_action"), nullable=False
    )
    decision: Mapped[PolicyDecisionOutcome] = mapped_column(
        enum_column(PolicyDecisionOutcome, "policy_decision_outcome"), nullable=False
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
