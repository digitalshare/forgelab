"""Authoritative MVP domain guardrails.

Every API handler, worker, and policy decision imports its boundaries from this
module so that agent counts, run limits, roles, actions, and supported languages
cannot drift between components. Infrastructure settings (connection strings,
provider keys) live in `forgelab_api.core.config` instead.

Two conventions matter here:

* **Durations are `timedelta`.** Each one also exposes a `_SECONDS` companion so
  callers never have to guess whether a bare number means seconds or minutes.
* **Role and action matching is exact.** Parsing is deliberately strict — a
  misspelled or differently-cased role string is rejected rather than coerced,
  because coercion on an authorization path can silently grant access.
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Final

__all__ = [
    "MVP_AGENT_COUNT",
    "MAX_ITERATIONS",
    "MAX_RUNTIME",
    "MAX_RUNTIME_SECONDS",
    "MAX_COMMANDS",
    "ACCESS_TOKEN_TTL",
    "ACCESS_TOKEN_TTL_SECONDS",
    "REFRESH_TOKEN_TTL",
    "REFRESH_TOKEN_TTL_SECONDS",
    "SANDBOX_CREDENTIAL_TTL",
    "SANDBOX_CREDENTIAL_TTL_SECONDS",
    "GITHUB_INSTALLATION_TOKEN_TTL",
    "GITHUB_INSTALLATION_TOKEN_TTL_SECONDS",
    "SupportedLanguage",
    "LANGUAGE_ALIASES",
    "ProjectRole",
    "ProjectAction",
    "SENSITIVE_ACTIONS",
    "AuditAction",
    "AuditOutcome",
    "RunBoundBreach",
    "UnsupportedValueError",
    "is_supported_language",
    "parse_language",
    "is_valid_role",
    "parse_role",
    "is_valid_action",
    "parse_action",
    "is_sensitive_action",
    "is_valid_agent_count",
    "check_run_bounds",
]


# --------------------------------------------------------------------------
# Agent fleet
# --------------------------------------------------------------------------

#: v0.1 runs exactly three agents against every challenge. This is a product
#: boundary, not a tunable — the arena UI, orchestrator, and scoring all assume
#: three lanes. Generalizing to N agents is explicitly out of scope for the MVP.
MVP_AGENT_COUNT: Final[int] = 3


# --------------------------------------------------------------------------
# Bounded agent loop
# --------------------------------------------------------------------------

#: Maximum plan/edit/test cycles before a run is terminated.
MAX_ITERATIONS: Final[int] = 8

#: Maximum wall-clock time for a single agent run.
MAX_RUNTIME: Final[timedelta] = timedelta(minutes=15)
MAX_RUNTIME_SECONDS: Final[int] = int(MAX_RUNTIME.total_seconds())

#: Maximum sandbox commands a single agent run may execute.
MAX_COMMANDS: Final[int] = 200


# --------------------------------------------------------------------------
# Credential lifetimes
# --------------------------------------------------------------------------

#: Bearer token lifetime. Deliberately short — access tokens are stateless, so a
#: leaked one stays usable until it expires.
ACCESS_TOKEN_TTL: Final[timedelta] = timedelta(minutes=15)
ACCESS_TOKEN_TTL_SECONDS: Final[int] = int(ACCESS_TOKEN_TTL.total_seconds())

#: Refresh cookie lifetime, and the expiry stamped on the server-side session
#: row. Rotation on every refresh keeps the window of a stolen token small.
REFRESH_TOKEN_TTL: Final[timedelta] = timedelta(days=7)
REFRESH_TOKEN_TTL_SECONDS: Final[int] = int(REFRESH_TOKEN_TTL.total_seconds())

#: Lease handed to a sandbox. Deliberately just longer than MAX_RUNTIME so a
#: credential cannot outlive the run it was minted for by any meaningful margin.
SANDBOX_CREDENTIAL_TTL: Final[timedelta] = timedelta(minutes=20)
SANDBOX_CREDENTIAL_TTL_SECONDS: Final[int] = int(SANDBOX_CREDENTIAL_TTL.total_seconds())

#: GitHub caps installation tokens at one hour; mirrored here so callers do not
#: request a longer lifetime than the provider will grant.
GITHUB_INSTALLATION_TOKEN_TTL: Final[timedelta] = timedelta(hours=1)
GITHUB_INSTALLATION_TOKEN_TTL_SECONDS: Final[int] = int(
    GITHUB_INSTALLATION_TOKEN_TTL.total_seconds()
)


# --------------------------------------------------------------------------
# Repository languages
# --------------------------------------------------------------------------


class SupportedLanguage(StrEnum):
    """Repository languages ForgeLab can evaluate in v0.1."""

    PYTHON = "python"
    NODEJS = "nodejs"


#: Aliases that map onto an approved MVP language. Anything absent from this
#: table is rejected — notably Java, Go, and Rust, which have no MVP toolchain.
#: `java` and `javascript` are distinct keys, so no prefix match can conflate them.
LANGUAGE_ALIASES: Final[dict[str, SupportedLanguage]] = {
    "python": SupportedLanguage.PYTHON,
    "python3": SupportedLanguage.PYTHON,
    "py": SupportedLanguage.PYTHON,
    "nodejs": SupportedLanguage.NODEJS,
    "node": SupportedLanguage.NODEJS,
    "node.js": SupportedLanguage.NODEJS,
    "javascript": SupportedLanguage.NODEJS,
    "js": SupportedLanguage.NODEJS,
    "typescript": SupportedLanguage.NODEJS,
    "ts": SupportedLanguage.NODEJS,
}


# --------------------------------------------------------------------------
# Roles and actions
# --------------------------------------------------------------------------


class ProjectRole(StrEnum):
    """Project membership roles."""

    OWNER = "owner"
    MAINTAINER = "maintainer"
    REVIEWER = "reviewer"
    OPERATOR = "operator"


class ProjectAction(StrEnum):
    """Actions a project member may attempt."""

    CONNECT_REPOSITORY = "connect_repository"
    LAUNCH_CHALLENGE = "launch_challenge"
    RERUN_FAILED_AGENT = "rerun_failed_agent"
    REVIEW_RESULT = "review_result"
    APPROVE_RESULT = "approve_result"
    CREATE_PULL_REQUEST = "create_pull_request"


#: Actions that require an explicit policy decision and an audit record.
#: Every current action is sensitive; the set exists so downstream policy code
#: asks a named question rather than assuming, and so future non-sensitive
#: actions can be added without changing call sites.
SENSITIVE_ACTIONS: Final[frozenset[ProjectAction]] = frozenset(ProjectAction)


class AuditAction(StrEnum):
    """Durable audit event names."""

    REPOSITORY_CONNECTED = "repository.connected"
    CHALLENGE_LAUNCHED = "challenge.launched"
    AGENT_RERUN_REQUESTED = "agent.rerun_requested"
    RESULT_REVIEWED = "result.reviewed"
    RESULT_APPROVED = "result.approved"
    PULL_REQUEST_CREATED = "pull_request.created"
    SANDBOX_CREATED = "sandbox.created"
    SANDBOX_DESTROYED = "sandbox.destroyed"
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_REVOKED = "credential.revoked"
    RUN_LIMIT_REACHED = "run.limit_reached"
    SESSION_ISSUED = "session.issued"
    SESSION_REFRESHED = "session.refreshed"
    SESSION_REVOKED = "session.revoked"
    SESSION_REPLAY_DETECTED = "session.replay_detected"
    SESSION_DENIED = "session.denied"


class AuditOutcome(StrEnum):
    """What happened, normalized across every kind of audited event.

    `DENY` is a decision that was evaluated and refused; `FAILURE` is an attempt
    that could not be evaluated at all — a malformed token, an unknown session.
    Collapsing them would make "was this refused, or did it break?" unanswerable
    from the audit trail.
    """

    PERMIT = "permit"
    DENY = "deny"
    FAILURE = "failure"
    SYSTEM = "system"


class RunBoundBreach(StrEnum):
    """Reason an agent run was terminated by the loop guard."""

    ITERATIONS = "max_iterations_reached"
    RUNTIME = "max_runtime_reached"
    COMMANDS = "max_commands_reached"


# Exact-match lookup sets backing the strict role/action parsers below.
_ROLE_VALUES: Final[frozenset[str]] = frozenset(role.value for role in ProjectRole)
_ACTION_VALUES: Final[frozenset[str]] = frozenset(action.value for action in ProjectAction)


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------


class UnsupportedValueError(ValueError):
    """Raised when a value falls outside an MVP boundary."""


def is_supported_language(value: str) -> bool:
    """Whether `value` names an approved MVP language, alias included."""
    if not isinstance(value, str):
        return False
    return value.strip().casefold() in LANGUAGE_ALIASES


def parse_language(value: str) -> SupportedLanguage:
    """Resolve `value` to a supported language.

    Language input arrives from repository detection and user forms, so casing
    and surrounding whitespace are normalized before an exact alias lookup.

    Raises:
        UnsupportedValueError: if the language has no MVP toolchain.
    """
    if not isinstance(value, str):
        raise UnsupportedValueError(f"language must be a string, got {type(value).__name__}")

    language = LANGUAGE_ALIASES.get(value.strip().casefold())
    if language is None:
        supported = ", ".join(sorted(LANGUAGE_ALIASES))
        raise UnsupportedValueError(f"unsupported language {value!r}; expected one of: {supported}")
    return language


def is_valid_role(value: str) -> bool:
    """Whether `value` is exactly a canonical role name."""
    if not isinstance(value, str):
        return False
    return value in _ROLE_VALUES


def parse_role(value: str) -> ProjectRole:
    """Resolve `value` to a role using exact matching.

    Deliberately case-sensitive: silently upcasing or trimming an authorization
    input would let a malformed role string grant access it should not.

    Raises:
        UnsupportedValueError: if the role is not a canonical name.
    """
    if not is_valid_role(value):
        roles = ", ".join(sorted(_ROLE_VALUES))
        raise UnsupportedValueError(f"unknown role {value!r}; expected one of: {roles}")
    return ProjectRole(value)


def is_valid_action(value: str) -> bool:
    """Whether `value` is exactly a canonical action name."""
    if not isinstance(value, str):
        return False
    return value in _ACTION_VALUES


def parse_action(value: str) -> ProjectAction:
    """Resolve `value` to an action using exact matching.

    Raises:
        UnsupportedValueError: if the action is not a canonical name.
    """
    if not is_valid_action(value):
        actions = ", ".join(sorted(_ACTION_VALUES))
        raise UnsupportedValueError(f"unknown action {value!r}; expected one of: {actions}")
    return ProjectAction(value)


def is_sensitive_action(action: ProjectAction) -> bool:
    """Whether `action` requires a policy decision and an audit record."""
    return action in SENSITIVE_ACTIONS


def is_valid_agent_count(count: int) -> bool:
    """Whether `count` matches the fixed MVP fleet size."""
    if isinstance(count, bool) or not isinstance(count, int):
        return False
    return count == MVP_AGENT_COUNT


def check_run_bounds(
    *,
    iterations: int,
    elapsed: timedelta,
    commands: int,
) -> RunBoundBreach | None:
    """Report the first run bound exceeded, or `None` while the run is in budget.

    Pure and side-effect free — the caller decides how to terminate and what to
    emit. Bounds are checked in the order a run realistically hits them.
    """
    if iterations >= MAX_ITERATIONS:
        return RunBoundBreach.ITERATIONS
    if elapsed >= MAX_RUNTIME:
        return RunBoundBreach.RUNTIME
    if commands >= MAX_COMMANDS:
        return RunBoundBreach.COMMANDS
    return None

