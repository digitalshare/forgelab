"""Deterministic rules for sensitive project actions.

Pure functions over value objects. No database, no clock, no I/O — given the
same actor role and resource state, `evaluate` always returns the same verdict.
That is what makes the decision safe to expose in an API, reproducible in a
test, and meaningful when read back out of the audit trail months later.

The role-to-action matrix here is **authoritative**. `require_project_roles`
sources its roles from `roles_for()` rather than restating them, so RBAC and
policy cannot drift apart and disagree about who may do what.

Resource state arrives as value objects rather than being read from tables:
challenges (WO-007), agent runs (WO-012), and evaluations (WO-038) do not exist
yet. When they land, the caller assembles these from real rows — the rules
themselves do not change.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from forgelab_api.domains.constants import MVP_AGENT_COUNT, ProjectAction, ProjectRole


class ChallengeState(StrEnum):
    """Where a challenge is in its lifecycle."""

    DRAFT = "draft"
    RUNNING = "running"
    EVALUATING = "evaluating"
    COMPLETE = "complete"
    FAILED = "failed"


class RunState(StrEnum):
    """Where a single agent run is in its lifecycle."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TERMINATED = "terminated"


class DenyCode(StrEnum):
    """Normalized refusal reasons.

    Stable strings, because they are persisted, queried, and eventually shown in
    a UI. Adding a code is cheap; changing one breaks stored history.
    """

    ROLE_NOT_PERMITTED = "role_not_permitted"
    NOT_A_MEMBER = "not_a_member"
    MISSING_RESOURCE_STATE = "missing_resource_state"
    CHALLENGE_ALREADY_ACTIVE = "challenge_already_active"
    RESULTS_NOT_READY = "results_not_ready"
    RUN_NOT_FAILED = "run_not_failed"
    EVALUATION_GATES_NOT_MET = "evaluation_gates_not_met"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"


#: Which roles may attempt which action. The single source of truth for both
#: the policy service and the RBAC dependency.
#:
#: Reviewer approves but cannot connect repositories or open pull requests;
#: Operator runs and reruns work but cannot approve its own output. Splitting
#: those two is the point of having four roles rather than admin/non-admin.
ACTION_ROLES: dict[ProjectAction, tuple[ProjectRole, ...]] = {
    ProjectAction.CONNECT_REPOSITORY: (ProjectRole.OWNER, ProjectRole.MAINTAINER),
    ProjectAction.LAUNCH_CHALLENGE: (
        ProjectRole.OWNER,
        ProjectRole.MAINTAINER,
        ProjectRole.OPERATOR,
    ),
    ProjectAction.RERUN_FAILED_AGENT: (
        ProjectRole.OWNER,
        ProjectRole.MAINTAINER,
        ProjectRole.OPERATOR,
    ),
    ProjectAction.REVIEW_RESULT: tuple(ProjectRole),
    ProjectAction.APPROVE_RESULT: (
        ProjectRole.OWNER,
        ProjectRole.MAINTAINER,
        ProjectRole.REVIEWER,
    ),
    ProjectAction.CREATE_PULL_REQUEST: (ProjectRole.OWNER, ProjectRole.MAINTAINER),
}


def roles_for(action: ProjectAction) -> tuple[ProjectRole, ...]:
    """Roles permitted to attempt `action`."""
    return ACTION_ROLES[action]


@dataclass(frozen=True)
class GateState:
    """Objective evaluation outcome for a candidate patch.

    `thresholds_met` is supplied by the evaluation pipeline rather than derived
    here — the policy service must not become a second place where the passing
    bar is defined.
    """

    tests_passed: int = 0
    tests_total: int = 0
    thresholds_met: bool = False

    @property
    def all_tests_passed(self) -> bool:
        return self.tests_total > 0 and self.tests_passed == self.tests_total


@dataclass(frozen=True)
class ApprovalState:
    """A human sign-off recorded against a project action."""

    approved: bool
    approver_user_id: uuid.UUID | None = None
    approver_role: ProjectRole | None = None
    action: ProjectAction | None = None
    challenge_id: uuid.UUID | None = None
    revoked: bool = False


@dataclass(frozen=True)
class ResourceState:
    """Everything the rules may need. Every field optional; rules say what they require."""

    challenge_state: ChallengeState | None = None
    run_state: RunState | None = None
    agent_count: int | None = None
    gates: GateState | None = None
    approval: ApprovalState | None = None
    challenge_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None


@dataclass(frozen=True)
class Verdict:
    """The answer, with a code for machines and a sentence for people."""

    permitted: bool
    code: DenyCode | None = None
    explanation: str = ""
    #: Extra context for the audit record. Never contains credentials.
    details: dict[str, object] = field(default_factory=dict)


_PERMITTED = Verdict(permitted=True, explanation="allowed")


def _deny(code: DenyCode, explanation: str, **details: object) -> Verdict:
    return Verdict(permitted=False, code=code, explanation=explanation, details=details)


def _approval_is_valid(
    approval: ApprovalState | None,
    *,
    action: ProjectAction,
    challenge_id: uuid.UUID | None,
) -> tuple[bool, str]:
    """Whether an approval actually authorizes *this* action on *this* challenge.

    An approval that is merely present proves nothing. It has to be granted, not
    revoked, given by someone whose role may approve, and scoped to the action
    and challenge in front of us — otherwise sign-off on one thing silently
    unlocks another.
    """
    if approval is None or not approval.approved:
        return False, "no human approval was supplied"
    if approval.revoked:
        return False, "the supplied approval has been revoked"
    if approval.approver_role is not None and approval.approver_role not in roles_for(
        ProjectAction.APPROVE_RESULT
    ):
        return False, "the approver's role may not approve results"
    if approval.action is not None and approval.action is not action:
        return False, "the approval was granted for a different action"
    if (
        challenge_id is not None
        and approval.challenge_id is not None
        and approval.challenge_id != challenge_id
    ):
        return False, "the approval was granted for a different challenge"
    return True, ""


def evaluate(
    *,
    action: ProjectAction,
    role: ProjectRole,
    state: ResourceState | None = None,
) -> Verdict:
    """Decide whether `role` may perform `action` given `state`.

    Role is checked first, so a caller who may not attempt the action at all
    learns that rather than which resource preconditions it would have failed.
    """
    resource = state or ResourceState()

    if role not in roles_for(action):
        return _deny(
            DenyCode.ROLE_NOT_PERMITTED,
            f"the {role.value} role may not {action.value.replace('_', ' ')}",
            role=role.value,
            allowed_roles=[r.value for r in roles_for(action)],
        )

    if action is ProjectAction.CONNECT_REPOSITORY:
        return _PERMITTED

    if action is ProjectAction.LAUNCH_CHALLENGE:
        return _evaluate_launch(resource)

    if action is ProjectAction.RERUN_FAILED_AGENT:
        return _evaluate_rerun(resource)

    if action is ProjectAction.REVIEW_RESULT:
        return _evaluate_review(resource)

    if action is ProjectAction.APPROVE_RESULT:
        return _evaluate_approve(resource)

    if action is ProjectAction.CREATE_PULL_REQUEST:
        return _evaluate_pull_request(resource)

    # Unreachable while ACTION_ROLES covers every ProjectAction, which a test
    # asserts. Denying is the safe direction if that ever stops being true.
    return _deny(
        DenyCode.ROLE_NOT_PERMITTED,
        f"no policy rule is defined for {action.value}",
        action=action.value,
    )


def _evaluate_launch(state: ResourceState) -> Verdict:
    if state.challenge_state is None:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            "the challenge state is required to decide whether it may be launched",
        )
    if state.challenge_state in {ChallengeState.RUNNING, ChallengeState.EVALUATING}:
        return _deny(
            DenyCode.CHALLENGE_ALREADY_ACTIVE,
            "this challenge is already running",
            challenge_state=state.challenge_state.value,
        )
    if state.agent_count is not None and state.agent_count != MVP_AGENT_COUNT:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            f"a challenge runs exactly {MVP_AGENT_COUNT} agents",
            agent_count=state.agent_count,
        )
    return _PERMITTED


def _evaluate_rerun(state: ResourceState) -> Verdict:
    if state.run_state is None:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            "the run state is required to decide whether it may be rerun",
        )
    # Only a failed or terminated run may be rerun. Rerunning a live one would
    # race two agents onto the same lane; rerunning a succeeded one would
    # discard a result someone may already be reviewing.
    if state.run_state not in {RunState.FAILED, RunState.TERMINATED}:
        return _deny(
            DenyCode.RUN_NOT_FAILED,
            "only a failed or terminated run may be rerun",
            run_state=state.run_state.value,
        )
    return _PERMITTED


def _evaluate_review(state: ResourceState) -> Verdict:
    if state.challenge_state is None:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            "the challenge state is required to decide whether results may be reviewed",
        )
    if state.challenge_state not in {ChallengeState.COMPLETE, ChallengeState.FAILED}:
        return _deny(
            DenyCode.RESULTS_NOT_READY,
            "results are not available until the challenge has finished",
            challenge_state=state.challenge_state.value,
        )
    return _PERMITTED


def _evaluate_approve(state: ResourceState) -> Verdict:
    if state.challenge_state is None:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            "the challenge state is required to decide whether a result may be approved",
        )
    if state.challenge_state is not ChallengeState.COMPLETE:
        return _deny(
            DenyCode.RESULTS_NOT_READY,
            "a result can only be approved once the challenge has completed",
            challenge_state=state.challenge_state.value,
        )
    return _PERMITTED


def _evaluate_pull_request(state: ResourceState) -> Verdict:
    """Gates, or an explicit human override. Never neither."""
    if state.challenge_state is None or state.gates is None:
        return _deny(
            DenyCode.MISSING_RESOURCE_STATE,
            "challenge state and evaluation gates are required before a pull request",
        )
    if state.challenge_state is not ChallengeState.COMPLETE:
        return _deny(
            DenyCode.RESULTS_NOT_READY,
            "a pull request can only be opened once the challenge has completed",
            challenge_state=state.challenge_state.value,
        )

    if state.gates.thresholds_met:
        return _PERMITTED

    # Gates failed. A human may still sign it off, but the approval has to
    # genuinely authorize this action on this challenge.
    valid, why_not = _approval_is_valid(
        state.approval, action=ProjectAction.CREATE_PULL_REQUEST, challenge_id=state.challenge_id
    )
    if state.approval is None:
        return _deny(
            DenyCode.APPROVAL_REQUIRED,
            "evaluation thresholds were not met, so a human approval is required",
            tests_passed=state.gates.tests_passed,
            tests_total=state.gates.tests_total,
        )
    if not valid:
        return _deny(
            DenyCode.APPROVAL_INVALID,
            f"evaluation thresholds were not met and {why_not}",
            tests_passed=state.gates.tests_passed,
            tests_total=state.gates.tests_total,
        )
    return Verdict(
        permitted=True,
        explanation="evaluation thresholds were not met but a human approved the pull request",
        details={"approval_override": True},
    )
