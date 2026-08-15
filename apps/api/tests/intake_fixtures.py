"""Fixtures for intake persistence tests.

Builds on the two-tenant identity graph and adds one challenge per source type —
GitHub issue, manual description, and curated sample — each with its three
agent-run lanes. All three exist because the source type changes which fields
are populated and which uniqueness rule applies, so testing one proves little
about the others.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.challenges import repository as intake_repo
from forgelab_api.domains.challenges.models import Challenge
from forgelab_api.domains.constants import ChallengeSource
from tests.identity_fixtures import IdentityFixture, seed_identity_graph


@dataclass
class IntakeFixture:
    """One challenge of each source type, in tenant alpha."""

    identity: IdentityFixture
    github_issue: Challenge
    manual: Challenge
    sample: Challenge


async def seed_intake_graph(session: AsyncSession) -> IntakeFixture:
    identity = await seed_identity_graph(session)
    tenant_id = identity.alpha.tenant.id
    project_id = identity.alpha.project.id

    github = await intake_repo.create_challenge_with_runs(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        repository_id=identity.alpha.repository.id,
        created_by_user_id=identity.alpha.owner.id,
        title="Fix duplicate user creation on POST /users",
        description="POST /users sometimes creates duplicate users under concurrency.",
        source_type=ChallengeSource.GITHUB_ISSUE,
        source_ref="1842",
        source_url="https://github.com/alpha/checkout-service/issues/1842",
        source_metadata={"labels": ["bug", "backend"]},
    )

    manual = await intake_repo.create_challenge_with_runs(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        repository_id=identity.alpha.repository.id,
        created_by_user_id=identity.alpha.owner.id,
        title="Fix the authentication timeout on dashboard refresh",
        description="Replace the synchronous token refresh with an async retry.",
        source_type=ChallengeSource.MANUAL,
    )

    sample = await intake_repo.create_challenge_with_runs(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        # No connected repository: a sample runs against a curated fixture.
        repository_id=None,
        created_by_user_id=identity.alpha.owner.id,
        title="Broken checkout API",
        description="Three seeded defects: a race condition, a discount "
        "miscalculation, and a missing validation.",
        source_type=ChallengeSource.SAMPLE,
        source_ref="checkout-api",
    )

    await session.flush()
    return IntakeFixture(
        identity=identity,
        github_issue=github.challenge,
        manual=manual.challenge,
        sample=sample.challenge,
    )
