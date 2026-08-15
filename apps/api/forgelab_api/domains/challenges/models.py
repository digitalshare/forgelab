"""Intake persistence: challenges, agent runs, and their result placeholders.

Four tables. Connected repositories are **not** among them — WO-002 already
delivered `repository_connections`, and a second repository table would be two
answers to one question.

Status columns use the same `ChallengeState` and `RunState` enums the policy
rules evaluate, so a challenge cannot be `complete` in the database and
something else to the rule that decides whether a pull request may be opened.

`evaluation_summaries` and `artifact_metadata` are deliberately thin. The real
evaluation model arrives with WO-038 and scoring with WO-042; these exist so a
run has somewhere to put its objective results and its artifact references from
the start, rather than those being bolted on later.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
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
    MVP_AGENT_COUNT,
    ArtifactKind,
    ChallengeSource,
    ChallengeState,
    RunState,
)


class Challenge(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """One software task, given to exactly three agents."""

    __tablename__ = "challenges"
    __table_args__ = (
        Index("ix_challenges_project_status", "project_id", "status"),
        Index("ix_challenges_tenant_created", "tenant_id", "created_at"),
        # Re-importing the same GitHub issue must not silently create a second
        # challenge. Partial, so manual and sample challenges are unconstrained.
        Index(
            "uq_challenges_github_issue",
            "project_id",
            "source_ref",
            unique=True,
            postgresql_where=text(f"source_type = '{ChallengeSource.GITHUB_ISSUE.value}'"),
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Nullable: a sample challenge runs against a curated fixture rather than a
    #: connected repository, and a manual challenge may be drafted before one is
    #: linked. SET NULL rather than CASCADE — disconnecting a repository must not
    #: delete the history of what was run against it.
    repository_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("repository_connections.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    source_type: Mapped[ChallengeSource] = mapped_column(
        enum_column(ChallengeSource, "challenge_source"), nullable=False
    )
    #: Issue number, sample slug, or null for a manual description.
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    status: Mapped[ChallengeState] = mapped_column(
        enum_column(ChallengeState, "challenge_status"),
        nullable=False,
        default=ChallengeState.DRAFT,
    )
    agent_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=MVP_AGENT_COUNT
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentRun(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """One agent's attempt at one challenge.

    Created up front, three at a time, so the arena has three lanes to render
    before any agent has done anything.
    """

    __tablename__ = "agent_runs"
    __table_args__ = (
        # One run per lane. The orchestrator retrying a launch must not produce
        # a fourth agent.
        UniqueConstraint("challenge_id", "lane", name="uq_agent_runs_challenge_lane"),
        Index("ix_agent_runs_tenant_status", "tenant_id", "status"),
        Index("ix_agent_runs_challenge_lane", "challenge_id", "lane"),
    )

    challenge_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: 1-based lane number, matching the three columns of the arena UI.
    lane: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Stable label for the lane's role, e.g. "builder-a" or "specialist".
    agent_key: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[RunState] = mapped_column(
        enum_column(RunState, "agent_run_status"), nullable=False, default=RunState.PENDING
    )
    #: Daytona sandbox identifier, once one has been provisioned (WO-027).
    sandbox_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Which bound stopped the run, when one did (WO-033).
    termination_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvaluationSummary(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """Objective results for one run. One row per run, at most.

    A placeholder for WO-038 and WO-040. `thresholds_met` is the field the
    policy service reads for the pull-request gate — it is stored rather than
    derived so the passing bar stays defined in one place, the evaluation
    pipeline.
    """

    __tablename__ = "evaluation_summaries"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_evaluation_summaries_run"),
        Index("ix_evaluation_summaries_tenant", "tenant_id", "thresholds_met"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    tests_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tests_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    build_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    lint_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    security_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    files_changed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines_added: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines_removed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    thresholds_met: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: ForgeScore, once WO-042 computes it. Numeric rather than float so a
    #: ranking cannot shift on a rounding difference between machines.
    forge_score: Mapped[float | None] = mapped_column(Numeric(6, 2), nullable=True)


class ArtifactMetadata(UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, Base):
    """A pointer to something a run produced.

    Metadata only. Patches, logs, and test reports live in object storage; the
    architecture caps PostgreSQL at references for anything over ~1 MB.
    """

    __tablename__ = "artifact_metadata"
    __table_args__ = (Index("ix_artifact_metadata_run_kind", "run_id", "kind"),)

    run_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    kind: Mapped[ArtifactKind] = mapped_column(
        enum_column(ArtifactKind, "artifact_kind"), nullable=False
    )
    uri: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Content hash, so a served artifact can be shown to be the one evaluated.
    checksum: Mapped[str | None] = mapped_column(String(128), nullable=True)
