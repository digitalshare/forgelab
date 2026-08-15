"""Intake persistence: transactional creation, constraints, and tenant scoping."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.challenges import repository as intake_repo
from forgelab_api.domains.challenges.models import (
    AgentRun,
    ArtifactMetadata,
    Challenge,
    EvaluationSummary,
)
from forgelab_api.domains.constants import (
    MVP_AGENT_COUNT,
    ArtifactKind,
    ChallengeSource,
    ChallengeState,
    RunState,
)
from tests.intake_fixtures import IntakeFixture, seed_intake_graph


@pytest.fixture
async def intake(db_session: AsyncSession) -> IntakeFixture:
    return await seed_intake_graph(db_session)


async def _create(session: AsyncSession, intake: IntakeFixture, **overrides):
    kwargs = {
        "tenant_id": intake.identity.alpha.tenant.id,
        "project_id": intake.identity.alpha.project.id,
        "title": "A challenge",
        "description": "Do the thing",
        "source_type": ChallengeSource.MANUAL,
    }
    kwargs.update(overrides)
    return await intake_repo.create_challenge_with_runs(session, **kwargs)


# --------------------------------------------------------------------------
# Exactly three runs, atomically
# --------------------------------------------------------------------------


async def test_creation_produces_exactly_three_runs(
    db_session: AsyncSession, intake: IntakeFixture
):
    created = await _create(db_session, intake)
    assert len(created.runs) == MVP_AGENT_COUNT == 3


async def test_runs_occupy_distinct_numbered_lanes(
    db_session: AsyncSession, intake: IntakeFixture
):
    created = await _create(db_session, intake)
    assert sorted(run.lane for run in created.runs) == [1, 2, 3]
    assert len({run.agent_key for run in created.runs}) == 3


async def test_runs_start_pending_and_challenge_starts_draft(
    db_session: AsyncSession, intake: IntakeFixture
):
    created = await _create(db_session, intake)
    assert created.challenge.status is ChallengeState.DRAFT
    assert all(run.status is RunState.PENDING for run in created.runs)


async def test_runs_are_returned_in_lane_order(db_session: AsyncSession, intake: IntakeFixture):
    """The arena renders three columns; their order must not wander."""
    runs = await intake_repo.list_runs(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    assert [run.lane for run in runs] == [1, 2, 3]


@pytest.mark.parametrize("keys", [("only-one",), ("a", "b"), ("a", "b", "c", "d")])
async def test_wrong_number_of_agents_is_refused(
    db_session: AsyncSession, intake: IntakeFixture, keys: tuple[str, ...]
):
    with pytest.raises(intake_repo.IntakeError, match="exactly 3"):
        await _create(db_session, intake, agent_keys=keys)


async def test_duplicate_agent_keys_are_refused(
    db_session: AsyncSession, intake: IntakeFixture
):
    """Three lanes with the same label cannot be told apart in the UI or logs."""
    with pytest.raises(intake_repo.IntakeError, match="distinct"):
        await _create(db_session, intake, agent_keys=("same", "same", "other"))


async def test_a_fourth_run_cannot_be_added_to_a_challenge(
    db_session: AsyncSession, intake: IntakeFixture
):
    """The orchestrator retrying a launch must not produce a fourth agent."""
    db_session.add(
        AgentRun(
            tenant_id=intake.identity.alpha.tenant.id,
            challenge_id=intake.github_issue.id,
            lane=1,
            agent_key="intruder",
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.flush()


# --------------------------------------------------------------------------
# Rollback
# --------------------------------------------------------------------------


async def test_a_failed_creation_leaves_no_challenge_and_no_runs(
    db_session: AsyncSession, intake: IntakeFixture
):
    """A challenge with two lanes is not partially created — it is corrupt."""
    before_challenges = await db_session.scalar(select(func.count()).select_from(Challenge))
    before_runs = await db_session.scalar(select(func.count()).select_from(AgentRun))

    with pytest.raises(IntegrityError):
        # A project that does not exist: the challenge insert fails after the
        # savepoint has opened.
        await _create(db_session, intake, project_id=uuid.uuid4())

    assert await db_session.scalar(select(func.count()).select_from(Challenge)) == before_challenges
    assert await db_session.scalar(select(func.count()).select_from(AgentRun)) == before_runs


async def test_the_outer_transaction_survives_a_failed_creation(
    db_session: AsyncSession, intake: IntakeFixture
):
    """The savepoint is what lets a caller record the failure afterwards."""
    with pytest.raises(IntegrityError):
        await _create(db_session, intake, project_id=uuid.uuid4())

    recovered = await _create(db_session, intake, title="After the failure")
    assert recovered.challenge.id is not None


async def test_a_duplicate_issue_rolls_back_cleanly(
    db_session: AsyncSession, intake: IntakeFixture
):
    before = await db_session.scalar(select(func.count()).select_from(AgentRun))

    with pytest.raises(IntegrityError):
        await _create(
            db_session,
            intake,
            source_type=ChallengeSource.GITHUB_ISSUE,
            source_ref=intake.github_issue.source_ref,
        )

    assert await db_session.scalar(select(func.count()).select_from(AgentRun)) == before


# --------------------------------------------------------------------------
# Source types
# --------------------------------------------------------------------------


async def test_the_same_issue_cannot_be_imported_twice(
    db_session: AsyncSession, intake: IntakeFixture
):
    with pytest.raises(IntegrityError):
        await _create(
            db_session,
            intake,
            source_type=ChallengeSource.GITHUB_ISSUE,
            source_ref=intake.github_issue.source_ref,
        )


async def test_a_github_issue_challenge_needs_a_reference(
    db_session: AsyncSession, intake: IntakeFixture
):
    with pytest.raises(intake_repo.IntakeError, match="source_ref"):
        await _create(db_session, intake, source_type=ChallengeSource.GITHUB_ISSUE)


async def test_manual_challenges_are_not_constrained_by_the_issue_index(
    db_session: AsyncSession, intake: IntakeFixture
):
    """The uniqueness rule is partial, so manual challenges may repeat freely."""
    await _create(db_session, intake, title="One", source_type=ChallengeSource.MANUAL)
    await _create(db_session, intake, title="Two", source_type=ChallengeSource.MANUAL)


async def test_a_sample_challenge_needs_no_connected_repository(
    intake: IntakeFixture
):
    assert intake.sample.repository_id is None
    assert intake.sample.source_ref == "checkout-api"


async def test_issue_metadata_round_trips(intake: IntakeFixture):
    assert intake.github_issue.source_metadata["labels"] == ["bug", "backend"]
    assert intake.github_issue.source_url is not None


async def test_an_unknown_source_type_is_rejected_by_the_database(
    db_session: AsyncSession, intake: IntakeFixture
):
    """Raw SQL bypasses the Python enum; the CHECK constraint must not."""
    from sqlalchemy import text

    with pytest.raises(DBAPIError):
        await db_session.execute(
            text(
                "INSERT INTO challenges (id, tenant_id, project_id, title, description, "
                "source_type, source_metadata, status, agent_count, created_at, updated_at) "
                "VALUES (:id, :tenant, :project, 't', 'd', 'telepathy', '{}'::jsonb, "
                "'draft', 3, now(), now())"
            ),
            {
                "id": uuid.uuid4(),
                "tenant": intake.identity.alpha.tenant.id,
                "project": intake.identity.alpha.project.id,
            },
        )


async def test_lookup_by_issue_reference_supports_idempotent_intake(
    db_session: AsyncSession, intake: IntakeFixture
):
    found = await intake_repo.find_challenge_by_issue(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        project_id=intake.identity.alpha.project.id,
        source_ref="1842",
    )
    assert found is not None
    assert found.id == intake.github_issue.id


# --------------------------------------------------------------------------
# Tenant and project scoping
# --------------------------------------------------------------------------


async def test_challenge_lookup_is_tenant_scoped(
    db_session: AsyncSession, intake: IntakeFixture
):
    found = await intake_repo.get_challenge(
        db_session,
        tenant_id=intake.identity.beta.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    assert found is None

    direct = await db_session.get(Challenge, intake.github_issue.id)
    assert direct is not None, "the other tenant's challenge must genuinely exist"


async def test_challenge_listing_is_tenant_scoped(
    db_session: AsyncSession, intake: IntakeFixture
):
    assert list(
        await intake_repo.list_challenges(
            db_session, tenant_id=intake.identity.beta.tenant.id
        )
    ) == []


async def test_challenge_listing_can_narrow_to_a_project_and_status(
    db_session: AsyncSession, intake: IntakeFixture
):
    rows = await intake_repo.list_challenges(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        project_id=intake.identity.alpha.project.id,
        status=ChallengeState.DRAFT,
    )
    assert {c.id for c in rows} >= {intake.github_issue.id, intake.manual.id, intake.sample.id}


async def test_run_listing_is_tenant_scoped(db_session: AsyncSession, intake: IntakeFixture):
    runs = await intake_repo.list_runs(
        db_session,
        tenant_id=intake.identity.beta.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    assert list(runs) == []


async def test_issue_lookup_is_tenant_scoped(db_session: AsyncSession, intake: IntakeFixture):
    found = await intake_repo.find_challenge_by_issue(
        db_session,
        tenant_id=intake.identity.beta.tenant.id,
        project_id=intake.identity.alpha.project.id,
        source_ref="1842",
    )
    assert found is None


async def test_run_count_is_tenant_scoped(db_session: AsyncSession, intake: IntakeFixture):
    assert (
        await intake_repo.count_runs(
            db_session,
            tenant_id=intake.identity.alpha.tenant.id,
            challenge_id=intake.github_issue.id,
        )
        == MVP_AGENT_COUNT
    )
    assert (
        await intake_repo.count_runs(
            db_session,
            tenant_id=intake.identity.beta.tenant.id,
            challenge_id=intake.github_issue.id,
        )
        == 0
    )


# --------------------------------------------------------------------------
# Cascades and result placeholders
# --------------------------------------------------------------------------


async def test_deleting_a_challenge_removes_its_runs(
    db_session: AsyncSession, intake: IntakeFixture
):
    challenge = await db_session.get(Challenge, intake.manual.id)
    await db_session.delete(challenge)
    await db_session.flush()

    remaining = await db_session.scalar(
        select(func.count()).select_from(AgentRun).where(AgentRun.challenge_id == intake.manual.id)
    )
    assert remaining == 0


async def test_disconnecting_a_repository_keeps_the_challenge_history(
    db_session: AsyncSession, intake: IntakeFixture
):
    """SET NULL, not CASCADE — what was run must survive the connection."""
    from forgelab_api.domains.identity.models import RepositoryConnection

    repository = await db_session.get(RepositoryConnection, intake.identity.alpha.repository.id)
    await db_session.delete(repository)
    await db_session.flush()

    challenge = await db_session.get(Challenge, intake.github_issue.id)
    await db_session.refresh(challenge)
    assert challenge is not None
    assert challenge.repository_id is None


async def test_a_run_has_at_most_one_evaluation_summary(
    db_session: AsyncSession, intake: IntakeFixture
):
    runs = await intake_repo.list_runs(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    run = runs[0]
    for _ in range(2):
        db_session.add(
            EvaluationSummary(
                tenant_id=run.tenant_id,
                run_id=run.id,
                challenge_id=run.challenge_id,
                tests_passed=15,
                tests_total=15,
                thresholds_met=True,
            )
        )
    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_evaluation_summary_round_trips(
    db_session: AsyncSession, intake: IntakeFixture
):
    runs = await intake_repo.list_runs(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    run = runs[0]
    db_session.add(
        EvaluationSummary(
            tenant_id=run.tenant_id,
            run_id=run.id,
            challenge_id=run.challenge_id,
            tests_passed=15,
            tests_total=15,
            thresholds_met=True,
            forge_score=97.20,
        )
    )
    await db_session.flush()

    summary = await intake_repo.get_evaluation_summary(
        db_session, tenant_id=run.tenant_id, run_id=run.id
    )
    assert summary is not None
    assert summary.thresholds_met is True
    assert float(summary.forge_score) == 97.20


async def test_artifacts_are_listed_for_a_run(db_session: AsyncSession, intake: IntakeFixture):
    runs = await intake_repo.list_runs(
        db_session,
        tenant_id=intake.identity.alpha.tenant.id,
        challenge_id=intake.github_issue.id,
    )
    run = runs[0]
    db_session.add(
        ArtifactMetadata(
            tenant_id=run.tenant_id,
            run_id=run.id,
            challenge_id=run.challenge_id,
            kind=ArtifactKind.PATCH,
            uri="s3://forgelab/patches/abc.diff",
            size_bytes=2048,
            checksum="sha256:abc",
        )
    )
    await db_session.flush()

    artifacts = await intake_repo.list_artifacts(
        db_session, tenant_id=run.tenant_id, run_id=run.id
    )
    assert [a.kind for a in artifacts] == [ArtifactKind.PATCH]
    assert artifacts[0].uri.startswith("s3://")
