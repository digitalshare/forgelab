# Project action policy

Delivered by WO-010. RBAC answers *"are you a member with role X?"*. Policy
answers *"given role X and the current state of this challenge, may you do Z?"*.

## The two layers

| | RBAC (WO-008) | Policy (WO-010) |
|---|---|---|
| Question | Member with an accepted role? | Permitted given resource state? |
| On refusal | Raises → 403/404 | Returns a verdict |
| Use for | Simple endpoints | Anything gated on state |

`ACTION_ROLES` in `domains/policy/rules.py` is the **authoritative** role
matrix. `require_project_roles` sources its roles from `roles_for()` and
`ADMIN_ROLES` is derived from it, so the two layers cannot drift into
disagreeing about who may attempt an action.

## Asking

```python
from forgelab_api.domains.policy import service as policy
from forgelab_api.domains.policy.rules import ChallengeState, GateState, ResourceState

outcome = await policy.check_action(
    session,
    actor_user_id=actor.user_id,
    tenant_id=actor.tenant_id,
    project_id=project_id,
    action=ProjectAction.CREATE_PULL_REQUEST,
    state=ResourceState(
        challenge_state=ChallengeState.COMPLETE,
        challenge_id=challenge.id,
        gates=GateState(tests_passed=15, tests_total=15, thresholds_met=True),
    ),
    request_id=get_request_id(request),
)
if not outcome.permitted:
    raise HTTPException(403, outcome.explanation)
```

`check_action` **never raises for a refusal** — a refusal is an answer. Even
non-membership comes back as a `not_a_member` denial, so a caller can ask about
an action it is not allowed to take and get a usable reply. That is the whole
point: the dashboard needs to know whether to offer a button.

`POST /projects/{project_id}/policy/check` exposes this over HTTP and always
returns 200 for an authenticated caller.

## The role matrix

| Action | Owner | Maintainer | Reviewer | Operator |
|---|:-:|:-:|:-:|:-:|
| `connect_repository` | ✓ | ✓ | | |
| `launch_challenge` | ✓ | ✓ | | ✓ |
| `rerun_failed_agent` | ✓ | ✓ | | ✓ |
| `review_result` | ✓ | ✓ | ✓ | ✓ |
| `approve_result` | ✓ | ✓ | ✓ | |
| `create_pull_request` | ✓ | ✓ | | |

Operator runs and reruns work but cannot approve its own output; Reviewer
approves but cannot open pull requests. Separating those two is the reason there
are four roles rather than admin/non-admin.

## State rules

| Action | Requires |
|---|---|
| `connect_repository` | nothing |
| `launch_challenge` | challenge not already `running` or `evaluating`; exactly three agents |
| `rerun_failed_agent` | run is `failed` or `terminated` |
| `review_result` | challenge `complete` or `failed` |
| `approve_result` | challenge `complete` |
| `create_pull_request` | challenge `complete`, **and** gates met or a valid approval |

A failed challenge is still reviewable — a failure is exactly what an operator
needs to look at. Rerunning a live run would race two agents onto one lane;
rerunning a succeeded one would discard a result someone may be reviewing.

Missing state is a denial (`missing_resource_state`), never an assumption. The
policy service will not guess that a challenge is complete.

## The pull-request gate

Thresholds met → permitted. Thresholds **not** met → permitted only with a valid
human approval, recorded as `approval_override` in the decision metadata.

An approval that is merely *present* proves nothing. To count it must be
granted, not revoked, given by a role that may approve, and scoped to **this
action** and **this challenge**. Otherwise sign-off on one thing silently
unlocks another.

`thresholds_met` is supplied by the evaluation pipeline, not derived here — the
policy service must not become a second place where the passing bar is defined.

## Every decision is recorded twice

Deliberately, and required by the story. A `policy_decisions` row answers *"what
did we decide about pull requests on this challenge?"*; an audit event
(`policy.evaluated`) answers *"what happened during that request?"*. Both are
written inside `check_action` so no caller has to remember either.

Nothing is committed — the caller owns the transaction. On a path that raises,
commit first or the decision is lost with the request; see `docs/audit.md`.

A non-member's decision row records **no project id**, the same non-disclosure
rule the RBAC layer applies.

## Reason codes

`DenyCode` values are persisted, queried, and eventually shown in a UI. Adding a
code is cheap; **changing one breaks stored history**. Each verdict carries both
a code for machines and a sentence for people.

## When challenges and runs become real

`ResourceState` is assembled by the caller from value objects, because
challenges (WO-007), agent runs (WO-012), and evaluations (WO-038) do not exist
yet. When they land, the caller builds `ResourceState` from real rows — the
rules do not change. Do not move table lookups into `rules.py`; its purity is
what makes verdicts reproducible in tests and meaningful when read back out of
the audit trail months later.
