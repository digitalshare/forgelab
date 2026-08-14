"""Fixtures for authorization tests.

Extends the two-tenant identity graph with every membership shape RBAC has to
distinguish: each of the four roles, a user with no membership at all, a user
whose membership was revoked, and a second project in the same tenant so
cross-*project* denial can be tested separately from cross-*tenant* denial.

Those last two matter independently. A helper that filters by tenant but forgets
project would pass every cross-tenant test and still leak between projects.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.constants import ProjectRole
from forgelab_api.domains.identity.models import (
    MembershipStatus,
    Project,
    ProjectMembership,
    User,
)
from tests.identity_fixtures import IdentityFixture, seed_identity_graph


@dataclass
class RbacFixture:
    """An identity graph plus the membership shapes authorization must separate."""

    identity: IdentityFixture

    #: One user per role, all on `identity.alpha.project`.
    owner: User
    maintainer: User
    reviewer: User
    operator: User

    #: In the tenant, but holds no membership on any project.
    non_member: User

    #: Held a membership on the project; it was revoked.
    revoked_member: User

    #: A second project in the same tenant. `owner` is NOT a member of it.
    other_project: Project

    #: A user in the *other* tenant, with a valid membership of their own.
    foreign_user: User


async def _add_member(
    session: AsyncSession,
    *,
    tenant_id,
    project_id,
    email: str,
    display_name: str,
    role: ProjectRole,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> User:
    user = User(tenant_id=tenant_id, email=email, display_name=display_name)
    session.add(user)
    await session.flush()

    session.add(
        ProjectMembership(
            tenant_id=tenant_id,
            project_id=project_id,
            user_id=user.id,
            role=role,
            status=status,
        )
    )
    await session.flush()
    return user


async def seed_rbac_graph(session: AsyncSession) -> RbacFixture:
    identity = await seed_identity_graph(session)
    tenant_id = identity.alpha.tenant.id
    project_id = identity.alpha.project.id

    maintainer = await _add_member(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        email="maintainer@alpha.example",
        display_name="Alpha Maintainer",
        role=ProjectRole.MAINTAINER,
    )
    operator = await _add_member(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        email="operator@alpha.example",
        display_name="Alpha Operator",
        role=ProjectRole.OPERATOR,
    )
    revoked_member = await _add_member(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        email="revoked@alpha.example",
        display_name="Alpha Former Member",
        role=ProjectRole.MAINTAINER,
        status=MembershipStatus.REVOKED,
    )

    non_member = User(
        tenant_id=tenant_id,
        email="outsider@alpha.example",
        display_name="Alpha Outsider",
    )
    other_project = Project(
        tenant_id=tenant_id, name="Alpha Second Project", slug="alpha-second"
    )
    session.add_all([non_member, other_project])
    await session.flush()

    return RbacFixture(
        identity=identity,
        owner=identity.alpha.owner,
        maintainer=maintainer,
        reviewer=identity.alpha.reviewer,
        operator=operator,
        non_member=non_member,
        revoked_member=revoked_member,
        other_project=other_project,
        foreign_user=identity.beta.owner,
    )
