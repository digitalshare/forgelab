"""Unit tests for the shared MVP domain guardrails."""

from __future__ import annotations

from datetime import timedelta

import pytest

from forgelab_api.domains.constants import (
    ACCESS_TOKEN_TTL,
    ACCESS_TOKEN_TTL_SECONDS,
    GITHUB_INSTALLATION_TOKEN_TTL,
    GITHUB_INSTALLATION_TOKEN_TTL_SECONDS,
    LANGUAGE_ALIASES,
    MAX_COMMANDS,
    MAX_ITERATIONS,
    MAX_RUNTIME,
    MAX_RUNTIME_SECONDS,
    MVP_AGENT_COUNT,
    REFRESH_TOKEN_TTL,
    REFRESH_TOKEN_TTL_SECONDS,
    SANDBOX_CREDENTIAL_TTL,
    SANDBOX_CREDENTIAL_TTL_SECONDS,
    SENSITIVE_ACTIONS,
    AuditAction,
    ProjectAction,
    ProjectRole,
    RunBoundBreach,
    SupportedLanguage,
    UnsupportedValueError,
    check_run_bounds,
    is_sensitive_action,
    is_supported_language,
    is_valid_action,
    is_valid_agent_count,
    is_valid_role,
    parse_action,
    parse_language,
    parse_role,
)
from tests.fixtures import (
    SAMPLE_ACTION_CONTEXTS,
    SAMPLE_CHALLENGE,
    SAMPLE_PROJECT,
    SAMPLE_REPOSITORY,
    SAMPLE_SUPPORTED_LANGUAGE_INPUTS,
    SAMPLE_TENANT,
    SAMPLE_UNSUPPORTED_LANGUAGE_INPUTS,
)

# --------------------------------------------------------------------------
# Scalar boundaries
# --------------------------------------------------------------------------


def test_mvp_runs_exactly_three_agents():
    assert MVP_AGENT_COUNT == 3


def test_run_bounds_match_the_product_limits():
    assert MAX_ITERATIONS == 8
    assert MAX_RUNTIME == timedelta(minutes=15)
    assert MAX_COMMANDS == 200


def test_duration_companions_are_expressed_in_seconds():
    """The `_SECONDS` values must agree with their timedelta, not restate a guess."""
    assert MAX_RUNTIME_SECONDS == 900
    assert ACCESS_TOKEN_TTL_SECONDS == int(ACCESS_TOKEN_TTL.total_seconds())
    assert REFRESH_TOKEN_TTL_SECONDS == int(REFRESH_TOKEN_TTL.total_seconds())
    assert SANDBOX_CREDENTIAL_TTL_SECONDS == int(SANDBOX_CREDENTIAL_TTL.total_seconds())
    assert GITHUB_INSTALLATION_TOKEN_TTL_SECONDS == int(
        GITHUB_INSTALLATION_TOKEN_TTL.total_seconds()
    )


def test_access_and_refresh_ttls_match_the_session_contract():
    """WO-003 fixes these values: a 15-minute access token, a 7-day refresh."""
    assert ACCESS_TOKEN_TTL == timedelta(minutes=15)
    assert REFRESH_TOKEN_TTL == timedelta(days=7)
    assert ACCESS_TOKEN_TTL < REFRESH_TOKEN_TTL


def test_sandbox_credential_outlives_a_full_length_run():
    """A lease that expires mid-run would fail the agent; one that lingers is a risk."""
    assert SANDBOX_CREDENTIAL_TTL > MAX_RUNTIME
    assert SANDBOX_CREDENTIAL_TTL <= MAX_RUNTIME + timedelta(minutes=10)


def test_github_installation_token_respects_provider_ceiling():
    assert GITHUB_INSTALLATION_TOKEN_TTL <= timedelta(hours=1)


# --------------------------------------------------------------------------
# Enum membership
# --------------------------------------------------------------------------


def test_supported_languages_are_python_and_nodejs_only():
    assert {lang.value for lang in SupportedLanguage} == {"python", "nodejs"}


def test_project_roles_cover_the_four_mvp_roles():
    assert {role.value for role in ProjectRole} == {
        "owner",
        "maintainer",
        "reviewer",
        "operator",
    }


def test_project_actions_cover_every_sensitive_operation():
    assert {action.value for action in ProjectAction} == {
        "connect_repository",
        "launch_challenge",
        "rerun_failed_agent",
        "review_result",
        "approve_result",
        "create_pull_request",
    }


def test_every_action_is_currently_sensitive():
    assert SENSITIVE_ACTIONS == frozenset(ProjectAction)
    assert all(is_sensitive_action(action) for action in ProjectAction)


def test_audit_actions_are_namespaced_and_unique():
    values = [action.value for action in AuditAction]
    assert len(values) == len(set(values))
    assert all("." in value for value in values)


def test_run_bound_breach_reasons_are_distinct():
    assert {breach.value for breach in RunBoundBreach} == {
        "max_iterations_reached",
        "max_runtime_reached",
        "max_commands_reached",
    }


# --------------------------------------------------------------------------
# Language validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("value", "expected"), SAMPLE_SUPPORTED_LANGUAGE_INPUTS)
def test_supported_language_inputs_resolve(value: str, expected: SupportedLanguage):
    assert is_supported_language(value)
    assert parse_language(value) is expected


@pytest.mark.parametrize("value", SAMPLE_UNSUPPORTED_LANGUAGE_INPUTS)
def test_unsupported_languages_are_rejected(value: str):
    assert not is_supported_language(value)
    with pytest.raises(UnsupportedValueError):
        parse_language(value)


def test_java_is_not_confused_with_javascript():
    """An alias table, not a prefix match — `java` must not resolve via `javascript`."""
    assert parse_language("javascript") is SupportedLanguage.NODEJS
    with pytest.raises(UnsupportedValueError):
        parse_language("java")


def test_language_error_names_the_accepted_values():
    with pytest.raises(UnsupportedValueError, match="unsupported language"):
        parse_language("rust")


def test_non_string_language_is_rejected_without_raising_typeerror():
    assert not is_supported_language(None)  # type: ignore[arg-type]
    with pytest.raises(UnsupportedValueError):
        parse_language(None)  # type: ignore[arg-type]


def test_every_alias_maps_to_a_real_language():
    assert all(isinstance(v, SupportedLanguage) for v in LANGUAGE_ALIASES.values())


# --------------------------------------------------------------------------
# Role and action validation — exact matching on the authorization path
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", list(ProjectRole))
def test_canonical_roles_parse(role: ProjectRole):
    assert is_valid_role(role.value)
    assert parse_role(role.value) is role


@pytest.mark.parametrize("value", ["Owner", "OWNER", " owner", "owner ", "admin", "", "reviewe"])
def test_miscased_or_misspelled_roles_are_rejected(value: str):
    """Coercing an authorization input could grant access it should not."""
    assert not is_valid_role(value)
    with pytest.raises(UnsupportedValueError):
        parse_role(value)


@pytest.mark.parametrize("action", list(ProjectAction))
def test_canonical_actions_parse(action: ProjectAction):
    assert is_valid_action(action.value)
    assert parse_action(action.value) is action


@pytest.mark.parametrize(
    "value", ["Launch_Challenge", "LAUNCH_CHALLENGE", "launch challenge", "delete_project", ""]
)
def test_invalid_actions_are_rejected(value: str):
    assert not is_valid_action(value)
    with pytest.raises(UnsupportedValueError):
        parse_action(value)


def test_non_string_role_and_action_inputs_are_rejected():
    assert not is_valid_role(None)  # type: ignore[arg-type]
    assert not is_valid_action(42)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Agent count and run bounds
# --------------------------------------------------------------------------


def test_only_three_is_a_valid_agent_count():
    assert is_valid_agent_count(3)
    assert not is_valid_agent_count(2)
    assert not is_valid_agent_count(4)
    assert not is_valid_agent_count(0)
    assert not is_valid_agent_count(-3)


def test_booleans_are_not_accepted_as_agent_counts():
    """`True == 1` in Python; the guard must not let a bool slip through."""
    assert not is_valid_agent_count(True)  # type: ignore[arg-type]
    assert not is_valid_agent_count("3")  # type: ignore[arg-type]


def test_run_within_budget_reports_no_breach():
    assert check_run_bounds(iterations=0, elapsed=timedelta(0), commands=0) is None
    assert (
        check_run_bounds(
            iterations=MAX_ITERATIONS - 1,
            elapsed=MAX_RUNTIME - timedelta(seconds=1),
            commands=MAX_COMMANDS - 1,
        )
        is None
    )


@pytest.mark.parametrize(
    ("iterations", "elapsed", "commands", "expected"),
    [
        (MAX_ITERATIONS, timedelta(0), 0, RunBoundBreach.ITERATIONS),
        (0, MAX_RUNTIME, 0, RunBoundBreach.RUNTIME),
        (0, timedelta(0), MAX_COMMANDS, RunBoundBreach.COMMANDS),
        (MAX_ITERATIONS + 5, timedelta(hours=1), 999, RunBoundBreach.ITERATIONS),
    ],
)
def test_run_bounds_report_the_breach(
    iterations: int, elapsed: timedelta, commands: int, expected: RunBoundBreach
):
    assert check_run_bounds(iterations=iterations, elapsed=elapsed, commands=commands) is expected


def test_check_run_bounds_is_side_effect_free():
    """Called twice with identical inputs, it must answer identically."""
    args = {"iterations": 3, "elapsed": timedelta(minutes=5), "commands": 40}
    assert check_run_bounds(**args) == check_run_bounds(**args)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def test_sample_fixtures_are_internally_consistent():
    assert SAMPLE_PROJECT.tenant_id == SAMPLE_TENANT.id
    assert SAMPLE_REPOSITORY.project_id == SAMPLE_PROJECT.id
    assert SAMPLE_CHALLENGE.repository_id == SAMPLE_REPOSITORY.id
    assert SAMPLE_CHALLENGE.agent_count == MVP_AGENT_COUNT


def test_sample_repository_language_is_supported():
    assert is_supported_language(SAMPLE_REPOSITORY.language.value)


def test_sample_action_contexts_cover_every_action():
    assert {ctx.action for ctx in SAMPLE_ACTION_CONTEXTS} == set(ProjectAction)
    assert all(is_valid_role(ctx.role.value) for ctx in SAMPLE_ACTION_CONTEXTS)
