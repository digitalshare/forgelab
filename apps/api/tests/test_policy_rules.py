"""Policy rule matrix. Pure functions — no database, no clock, no fixtures."""

from __future__ import annotations

import uuid

import pytest

from forgelab_api.domains.constants import MVP_AGENT_COUNT, ProjectAction, ProjectRole
from forgelab_api.domains.policy.rules import (
    ACTION_ROLES,
    ApprovalState,
    ChallengeState,
    DenyCode,
    GateState,
    ResourceState,
    RunState,
    evaluate,
    roles_for,
)

CHALLENGE_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
OTHER_CHALLENGE_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

COMPLETE = ResourceState(challenge_state=ChallengeState.COMPLETE, challenge_id=CHALLENGE_ID)
GATES_PASSED = GateState(tests_passed=15, tests_total=15, thresholds_met=True)
GATES_FAILED = GateState(tests_passed=12, tests_total=15, thresholds_met=False)


def _pr_state(gates: GateState, approval: ApprovalState | None = None) -> ResourceState:
    return ResourceState(
        challenge_state=ChallengeState.COMPLETE,
        challenge_id=CHALLENGE_ID,
        gates=gates,
        approval=approval,
    )


def _approval(**overrides) -> ApprovalState:
    defaults = {
        "approved": True,
        "approver_user_id": uuid.uuid4(),
        "approver_role": ProjectRole.MAINTAINER,
        "action": ProjectAction.CREATE_PULL_REQUEST,
        "challenge_id": CHALLENGE_ID,
        "revoked": False,
    }
    defaults.update(overrides)
    return ApprovalState(**defaults)


# --------------------------------------------------------------------------
# The matrix itself
# --------------------------------------------------------------------------


def test_every_action_has_a_rule():
    """A missing entry would mean an action nobody can perform, silently."""
    assert set(ACTION_ROLES) == set(ProjectAction)


def test_no_action_is_open_to_nobody():
    assert all(roles for roles in ACTION_ROLES.values())


@pytest.mark.parametrize("action", list(ProjectAction))
def test_owner_may_attempt_every_action(action: ProjectAction):
    """Owner is not implicitly privileged elsewhere, so it must be listed here."""
    assert ProjectRole.OWNER in roles_for(action)


def test_operator_may_not_approve_its_own_output():
    """Separating who runs work from who signs it off is the point of four roles."""
    assert ProjectRole.OPERATOR not in roles_for(ProjectAction.APPROVE_RESULT)
    assert ProjectRole.OPERATOR in roles_for(ProjectAction.RERUN_FAILED_AGENT)


def test_reviewer_may_approve_but_not_open_a_pull_request():
    assert ProjectRole.REVIEWER in roles_for(ProjectAction.APPROVE_RESULT)
    assert ProjectRole.REVIEWER not in roles_for(ProjectAction.CREATE_PULL_REQUEST)


def test_every_role_may_review_results():
    assert set(roles_for(ProjectAction.REVIEW_RESULT)) == set(ProjectRole)


# --------------------------------------------------------------------------
# Role gate comes first
# --------------------------------------------------------------------------


@pytest.mark.parametrize("action", list(ProjectAction))
@pytest.mark.parametrize("role", list(ProjectRole))
def test_role_matrix_is_enforced_for_every_pair(action: ProjectAction, role: ProjectRole):
    verdict = evaluate(action=action, role=role, state=None)
    if role not in roles_for(action):
        assert not verdict.permitted
        assert verdict.code is DenyCode.ROLE_NOT_PERMITTED


def test_role_refusal_precedes_state_checks():
    """Learn that you may not act at all, not which preconditions you'd fail."""
    verdict = evaluate(action=ProjectAction.CREATE_PULL_REQUEST, role=ProjectRole.OPERATOR)
    assert verdict.code is DenyCode.ROLE_NOT_PERMITTED


def test_denials_explain_themselves_in_a_sentence():
    verdict = evaluate(action=ProjectAction.APPROVE_RESULT, role=ProjectRole.OPERATOR)
    assert "operator" in verdict.explanation
    assert verdict.explanation != verdict.code.value


# --------------------------------------------------------------------------
# Connect repository
# --------------------------------------------------------------------------


def test_connecting_a_repository_needs_no_resource_state():
    verdict = evaluate(action=ProjectAction.CONNECT_REPOSITORY, role=ProjectRole.MAINTAINER)
    assert verdict.permitted


# --------------------------------------------------------------------------
# Launch challenge
# --------------------------------------------------------------------------


def test_launch_requires_challenge_state():
    verdict = evaluate(action=ProjectAction.LAUNCH_CHALLENGE, role=ProjectRole.OWNER)
    assert verdict.code is DenyCode.MISSING_RESOURCE_STATE


@pytest.mark.parametrize(
    "state", [ChallengeState.DRAFT, ChallengeState.COMPLETE, ChallengeState.FAILED]
)
def test_launch_is_allowed_when_not_already_active(state: ChallengeState):
    verdict = evaluate(
        action=ProjectAction.LAUNCH_CHALLENGE,
        role=ProjectRole.OPERATOR,
        state=ResourceState(challenge_state=state),
    )
    assert verdict.permitted


@pytest.mark.parametrize("state", [ChallengeState.RUNNING, ChallengeState.EVALUATING])
def test_launch_is_refused_while_active(state: ChallengeState):
    verdict = evaluate(
        action=ProjectAction.LAUNCH_CHALLENGE,
        role=ProjectRole.OWNER,
        state=ResourceState(challenge_state=state),
    )
    assert verdict.code is DenyCode.CHALLENGE_ALREADY_ACTIVE


def test_launch_enforces_the_fixed_agent_count():
    verdict = evaluate(
        action=ProjectAction.LAUNCH_CHALLENGE,
        role=ProjectRole.OWNER,
        state=ResourceState(challenge_state=ChallengeState.DRAFT, agent_count=2),
    )
    assert not verdict.permitted

    ok = evaluate(
        action=ProjectAction.LAUNCH_CHALLENGE,
        role=ProjectRole.OWNER,
        state=ResourceState(challenge_state=ChallengeState.DRAFT, agent_count=MVP_AGENT_COUNT),
    )
    assert ok.permitted


# --------------------------------------------------------------------------
# Rerun a failed agent
# --------------------------------------------------------------------------


def test_rerun_requires_run_state():
    verdict = evaluate(action=ProjectAction.RERUN_FAILED_AGENT, role=ProjectRole.OPERATOR)
    assert verdict.code is DenyCode.MISSING_RESOURCE_STATE


@pytest.mark.parametrize("state", [RunState.FAILED, RunState.TERMINATED])
def test_rerun_is_allowed_for_a_dead_run(state: RunState):
    verdict = evaluate(
        action=ProjectAction.RERUN_FAILED_AGENT,
        role=ProjectRole.OPERATOR,
        state=ResourceState(run_state=state),
    )
    assert verdict.permitted


@pytest.mark.parametrize("state", [RunState.PENDING, RunState.RUNNING, RunState.SUCCEEDED])
def test_rerun_is_refused_for_a_live_or_successful_run(state: RunState):
    """Rerunning a live run races two agents; rerunning a good one discards it."""
    verdict = evaluate(
        action=ProjectAction.RERUN_FAILED_AGENT,
        role=ProjectRole.OWNER,
        state=ResourceState(run_state=state),
    )
    assert verdict.code is DenyCode.RUN_NOT_FAILED


# --------------------------------------------------------------------------
# Review and approve
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state", [ChallengeState.DRAFT, ChallengeState.RUNNING, ChallengeState.EVALUATING]
)
def test_review_is_refused_before_the_challenge_finishes(state: ChallengeState):
    verdict = evaluate(
        action=ProjectAction.REVIEW_RESULT,
        role=ProjectRole.REVIEWER,
        state=ResourceState(challenge_state=state),
    )
    assert verdict.code is DenyCode.RESULTS_NOT_READY


@pytest.mark.parametrize("state", [ChallengeState.COMPLETE, ChallengeState.FAILED])
def test_a_failed_challenge_is_still_reviewable(state: ChallengeState):
    """A failure is exactly what an operator needs to look at."""
    verdict = evaluate(
        action=ProjectAction.REVIEW_RESULT,
        role=ProjectRole.OPERATOR,
        state=ResourceState(challenge_state=state),
    )
    assert verdict.permitted


def test_approval_requires_a_completed_challenge():
    verdict = evaluate(
        action=ProjectAction.APPROVE_RESULT,
        role=ProjectRole.REVIEWER,
        state=ResourceState(challenge_state=ChallengeState.FAILED),
    )
    assert verdict.code is DenyCode.RESULTS_NOT_READY


def test_approval_is_allowed_on_a_completed_challenge():
    verdict = evaluate(
        action=ProjectAction.APPROVE_RESULT, role=ProjectRole.REVIEWER, state=COMPLETE
    )
    assert verdict.permitted


# --------------------------------------------------------------------------
# Pull request — gates, or an explicit override
# --------------------------------------------------------------------------


def test_pull_request_requires_gates_and_challenge_state():
    verdict = evaluate(action=ProjectAction.CREATE_PULL_REQUEST, role=ProjectRole.OWNER)
    assert verdict.code is DenyCode.MISSING_RESOURCE_STATE


def test_pull_request_is_allowed_when_gates_pass():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_PASSED),
    )
    assert verdict.permitted


def test_pull_request_is_refused_when_gates_fail_and_nobody_approved():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED),
    )
    assert verdict.code is DenyCode.APPROVAL_REQUIRED
    assert verdict.details["tests_passed"] == 12


def test_a_valid_human_approval_overrides_failed_gates():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval()),
    )
    assert verdict.permitted
    assert verdict.details["approval_override"] is True


def test_an_unapproved_approval_record_does_not_override():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval(approved=False)),
    )
    assert verdict.code is DenyCode.APPROVAL_INVALID


def test_a_revoked_approval_does_not_override():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval(revoked=True)),
    )
    assert verdict.code is DenyCode.APPROVAL_INVALID


def test_an_approval_from_a_role_that_cannot_approve_does_not_override():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval(approver_role=ProjectRole.OPERATOR)),
    )
    assert verdict.code is DenyCode.APPROVAL_INVALID


def test_an_approval_for_another_action_does_not_override():
    """Sign-off on one thing must not silently unlock another."""
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval(action=ProjectAction.APPROVE_RESULT)),
    )
    assert verdict.code is DenyCode.APPROVAL_INVALID


def test_an_approval_for_another_challenge_does_not_override():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=_pr_state(GATES_FAILED, _approval(challenge_id=OTHER_CHALLENGE_ID)),
    )
    assert verdict.code is DenyCode.APPROVAL_INVALID


def test_approval_is_not_required_when_gates_already_pass():
    """An override is for failing gates; it should not be demanded otherwise."""
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.MAINTAINER,
        state=_pr_state(GATES_PASSED, None),
    )
    assert verdict.permitted
    assert "approval_override" not in verdict.details


def test_pull_request_is_refused_before_the_challenge_completes():
    verdict = evaluate(
        action=ProjectAction.CREATE_PULL_REQUEST,
        role=ProjectRole.OWNER,
        state=ResourceState(
            challenge_state=ChallengeState.RUNNING, gates=GATES_PASSED, challenge_id=CHALLENGE_ID
        ),
    )
    assert verdict.code is DenyCode.RESULTS_NOT_READY


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_evaluation_is_deterministic():
    state = _pr_state(GATES_FAILED, _approval())
    first = evaluate(action=ProjectAction.CREATE_PULL_REQUEST, role=ProjectRole.OWNER, state=state)
    second = evaluate(action=ProjectAction.CREATE_PULL_REQUEST, role=ProjectRole.OWNER, state=state)
    assert first == second


def test_gate_helper_reports_full_pass():
    assert GATES_PASSED.all_tests_passed
    assert not GATES_FAILED.all_tests_passed
    assert not GateState().all_tests_passed
