"""Tenant-scoped data access for challenges and agent runs.

Same contract as the identity repository: `tenant_id` is a required keyword
argument on every read, and querying the models directly bypasses the isolation
guarantee.

`create_challenge_with_runs` is the reason this module exists. A challenge and
its three runs are one fact — a challenge with two lanes is not a partially
created challenge, it is a corrupt one — so they are written inside a SAVEPOINT
that rolls back as a unit even when the caller's outer transaction continues.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.challenges.models import (
    AgentRun,
    ArtifactMetadata,
    Challenge,
    EvaluationSummary,
)
from forgelab_api.domains.constants import (
    MVP_AGENT_COUNT,
    ChallengeSource,
    ChallengeState,
    RunState,
)

#: The three lanes of the MVP arena. Two independent builders and one specialist
#: with a different system prompt — the comparison is the product, so the lanes
#: are fixed rather than configurable.
DEFAULT_AGENT_KEYS: tuple[str, ...] = ("builder-a", "builder-b", "specialist")


class IntakeError(Exception):
    """A challenge could not be created as specified."""


@dataclass(frozen=True)
class CreatedChallenge:
    """A challenge and its lanes, returned together because they are one fact."""

    challenge: Challenge
    runs: list[AgentRun]


async def create_challenge_with_runs(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    title: str,
    description: str,
    source_type: ChallengeSource,
    repository_id: uuid.UUID | None = None,
    created_by_user_id: uuid.UUID | None = None,
    source_ref: str | None = None,
    source_url: str | None = None,
    source_metadata: dict[str, Any] | None = None,
    agent_keys: Sequence[str] = DEFAULT_AGENT_KEYS,
) -> CreatedChallenge:
    """Create a challenge and exactly three agent runs, atomically.

    Wrapped in a SAVEPOINT: if any insert fails — a duplicate GitHub issue, a
    bad foreign key — the challenge and every run it had created roll back
    together, and the caller's surrounding transaction survives to record the
    failure.

    Raises:
        IntakeError: `agent_keys` does not hold exactly `MVP_AGENT_COUNT`
            entries, or a GitHub-issue challenge arrives without a source
            reference to be unique on.
    """
    if len(agent_keys) != MVP_AGENT_COUNT:
        raise IntakeError(
            f"a challenge runs exactly {MVP_AGENT_COUNT} agents, got {len(agent_keys)}"
        )
    if len(set(agent_keys)) != len(agent_keys):
        raise IntakeError("agent keys must be distinct so lanes are identifiable")
    if source_type is ChallengeSource.GITHUB_ISSUE and not source_ref:
        raise IntakeError(
            "a GitHub issue challenge needs a source_ref; without one the same "
            "issue could be imported twice"
        )

    async with session.begin_nested():
        challenge = Challenge(
            tenant_id=tenant_id,
            project_id=project_id,
            repository_id=repository_id,
            created_by_user_id=created_by_user_id,
            title=title,
            description=description,
            source_type=source_type,
            source_ref=source_ref,
            source_url=source_url,
            source_metadata=source_metadata or {},
            status=ChallengeState.DRAFT,
            agent_count=MVP_AGENT_COUNT,
        )
        session.add(challenge)
        await session.flush()

        runs = [
            AgentRun(
                tenant_id=tenant_id,
                challenge_id=challenge.id,
                lane=index,
                agent_key=key,
                status=RunState.PENDING,
            )
            for index, key in enumerate(agent_keys, start=1)
        ]
        session.add_all(runs)
        await session.flush()

    return CreatedChallenge(challenge=challenge, runs=runs)


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------


async def get_challenge(
    session: AsyncSession, *, tenant_id: uuid.UUID, challenge_id: uuid.UUID
) -> Challenge | None:
    result = await session.execute(
        select(Challenge).where(
            Challenge.tenant_id == tenant_id, Challenge.id == challenge_id
        )
    )
    return result.scalar_one_or_none()


async def list_challenges(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID | None = None,
    status: ChallengeState | None = None,
    limit: int = 50,
) -> Sequence[Challenge]:
    query = select(Challenge).where(Challenge.tenant_id == tenant_id)
    if project_id is not None:
        query = query.where(Challenge.project_id == project_id)
    if status is not None:
        query = query.where(Challenge.status == status)
    result = await session.execute(query.order_by(Challenge.created_at.desc()).limit(limit))
    return result.scalars().all()


async def find_challenge_by_issue(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    source_ref: str,
) -> Challenge | None:
    """Look up an already-imported GitHub issue, so intake can be idempotent."""
    result = await session.execute(
        select(Challenge).where(
            Challenge.tenant_id == tenant_id,
            Challenge.project_id == project_id,
            Challenge.source_type == ChallengeSource.GITHUB_ISSUE,
            Challenge.source_ref == source_ref,
        )
    )
    return result.scalar_one_or_none()


async def list_runs(
    session: AsyncSession, *, tenant_id: uuid.UUID, challenge_id: uuid.UUID
) -> Sequence[AgentRun]:
    """The challenge's lanes, in lane order so the arena renders consistently."""
    result = await session.execute(
        select(AgentRun)
        .where(AgentRun.tenant_id == tenant_id, AgentRun.challenge_id == challenge_id)
        .order_by(AgentRun.lane)
    )
    return result.scalars().all()


async def get_run(
    session: AsyncSession, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> AgentRun | None:
    result = await session.execute(
        select(AgentRun).where(AgentRun.tenant_id == tenant_id, AgentRun.id == run_id)
    )
    return result.scalar_one_or_none()


async def count_runs(
    session: AsyncSession, *, tenant_id: uuid.UUID, challenge_id: uuid.UUID
) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(AgentRun)
        .where(AgentRun.tenant_id == tenant_id, AgentRun.challenge_id == challenge_id)
    )
    return int(result.scalar_one())


async def get_evaluation_summary(
    session: AsyncSession, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> EvaluationSummary | None:
    result = await session.execute(
        select(EvaluationSummary).where(
            EvaluationSummary.tenant_id == tenant_id, EvaluationSummary.run_id == run_id
        )
    )
    return result.scalar_one_or_none()


async def list_artifacts(
    session: AsyncSession, *, tenant_id: uuid.UUID, run_id: uuid.UUID
) -> Sequence[ArtifactMetadata]:
    result = await session.execute(
        select(ArtifactMetadata)
        .where(
            ArtifactMetadata.tenant_id == tenant_id, ArtifactMetadata.run_id == run_id
        )
        .order_by(ArtifactMetadata.kind)
    )
    return result.scalars().all()
