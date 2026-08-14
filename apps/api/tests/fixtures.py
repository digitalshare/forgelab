"""Deterministic sample values for identity, RBAC, policy, and audit tests.

Every value here is fixed and fake. No real credentials, tokens, or provider
keys — downstream tests can import these freely and run without network access.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from forgelab_api.domains.constants import (
    MVP_AGENT_COUNT,
    ProjectAction,
    ProjectRole,
    SupportedLanguage,
)

# Fixed UUIDs — stable across runs so assertions and snapshots stay meaningful.
SAMPLE_TENANT_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SAMPLE_PROJECT_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
SAMPLE_REPOSITORY_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")
SAMPLE_CHALLENGE_ID = uuid.UUID("44444444-4444-4444-8444-444444444444")
SAMPLE_OWNER_USER_ID = uuid.UUID("55555555-5555-4555-8555-555555555555")
SAMPLE_REVIEWER_USER_ID = uuid.UUID("66666666-6666-4666-8666-666666666666")


@dataclass(frozen=True)
class SampleTenant:
    id: uuid.UUID = SAMPLE_TENANT_ID
    name: str = "Acme Engineering"
    slug: str = "acme-engineering"


@dataclass(frozen=True)
class SampleProject:
    id: uuid.UUID = SAMPLE_PROJECT_ID
    tenant_id: uuid.UUID = SAMPLE_TENANT_ID
    name: str = "Checkout Service"


@dataclass(frozen=True)
class SampleRepository:
    id: uuid.UUID = SAMPLE_REPOSITORY_ID
    project_id: uuid.UUID = SAMPLE_PROJECT_ID
    full_name: str = "acme-engineering/checkout-service"
    default_branch: str = "main"
    language: SupportedLanguage = SupportedLanguage.PYTHON


@dataclass(frozen=True)
class SampleChallenge:
    id: uuid.UUID = SAMPLE_CHALLENGE_ID
    project_id: uuid.UUID = SAMPLE_PROJECT_ID
    repository_id: uuid.UUID = SAMPLE_REPOSITORY_ID
    title: str = "Fix duplicate user creation on POST /users"
    agent_count: int = MVP_AGENT_COUNT


@dataclass(frozen=True)
class SampleMembership:
    user_id: uuid.UUID
    project_id: uuid.UUID = SAMPLE_PROJECT_ID
    role: ProjectRole = ProjectRole.OWNER


SAMPLE_TENANT = SampleTenant()
SAMPLE_PROJECT = SampleProject()
SAMPLE_REPOSITORY = SampleRepository()
SAMPLE_CHALLENGE = SampleChallenge()
SAMPLE_OWNER_MEMBERSHIP = SampleMembership(user_id=SAMPLE_OWNER_USER_ID, role=ProjectRole.OWNER)
SAMPLE_REVIEWER_MEMBERSHIP = SampleMembership(
    user_id=SAMPLE_REVIEWER_USER_ID, role=ProjectRole.REVIEWER
)


@dataclass(frozen=True)
class SampleActionContext:
    """A single actor-attempts-action case for policy and audit tests."""

    role: ProjectRole
    action: ProjectAction
    tenant_id: uuid.UUID = SAMPLE_TENANT_ID
    project_id: uuid.UUID = SAMPLE_PROJECT_ID
    user_id: uuid.UUID = SAMPLE_OWNER_USER_ID
    labels: tuple[str, ...] = field(default=())


#: One context per action, owner-attributed — a baseline downstream RBAC tests
#: can narrow or re-role as needed.
SAMPLE_ACTION_CONTEXTS: tuple[SampleActionContext, ...] = tuple(
    SampleActionContext(role=ProjectRole.OWNER, action=action) for action in ProjectAction
)

#: Language strings that must resolve, paired with their canonical language.
SAMPLE_SUPPORTED_LANGUAGE_INPUTS: tuple[tuple[str, SupportedLanguage], ...] = (
    ("python", SupportedLanguage.PYTHON),
    ("Python3", SupportedLanguage.PYTHON),
    ("  py  ", SupportedLanguage.PYTHON),
    ("nodejs", SupportedLanguage.NODEJS),
    ("Node.js", SupportedLanguage.NODEJS),
    ("TypeScript", SupportedLanguage.NODEJS),
)

#: Language strings that must be rejected — no MVP toolchain exists for these.
SAMPLE_UNSUPPORTED_LANGUAGE_INPUTS: tuple[str, ...] = (
    "java",
    "go",
    "rust",
    "ruby",
    "c++",
    "",
    "pythonic",
)
