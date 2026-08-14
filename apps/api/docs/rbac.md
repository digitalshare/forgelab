# Project authorization

Delivered by WO-008. Every project-scoped endpoint asks the same question — may
*this actor*, in *this tenant*, perform *this action* on *this project*? — and
this answers it once, records the answer, and hands the handler the result.

## Using it

```python
from typing import Annotated
from fastapi import Depends

from forgelab_api.api.dependencies import require_project_roles
from forgelab_api.domains.constants import ProjectAction
from forgelab_api.domains.policy.rbac import ADMIN_ROLES, ProjectContext


@router.post("/projects/{project_id}/repositories")
async def connect_repository(
    context: Annotated[
        ProjectContext,
        Depends(require_project_roles(*ADMIN_ROLES,
                                      action=ProjectAction.CONNECT_REPOSITORY)),
    ],
) -> ...:
    # context.tenant_id, context.project_id, context.role are resolved and
    # authorized. Do not re-query membership.
```

Requirements: the route must have a `project_id` path parameter, and the action
must be a `ProjectAction`. The handler does not run unless authorization passed.

Role groupings: `ADMIN_ROLES` (Owner, Maintainer) and `ALL_ROLES` (membership is
the only requirement).

## There is no role hierarchy

`require_project_roles(ProjectRole.MAINTAINER)` does **not** admit an Owner.
Every accepted role is listed explicitly.

This is deliberate and it will occasionally surprise you. Hierarchies read as
convenient right up until someone inserts a role in the middle, at which point
permissions silently shift on endpoints nobody edited. Listing roles is more
verbose and says exactly what it means. If Owner should be allowed, write it
down.

## Status codes leak as little as possible

| Situation | Status |
|---|---|
| Not authenticated | `401` |
| Project absent, in another tenant, or actor is not a member | `404` |
| Actor is a member, wrong role | `403` |

The three `404` cases are deliberately indistinguishable. A `403` for a
non-member would confirm the project exists, letting anyone enumerate projects
by probing identifiers. Only a member can learn that a project exists.

Consequence: `DenyReason` has just two values. `PROJECT_NOT_FOUND` covers
absent, wrong-tenant, and no-membership; reporting them separately would
reintroduce the leak through the audit trail.

## Decisions are recorded

Both outcomes write a `policy_decisions` row — actor, tenant, project, action,
decision, reason, and metadata carrying the actor's role and the accepted set.
A denial nobody recorded cannot be investigated, and an allow-only trail cannot
answer "who tried".

The dependency **commits** the decision itself, before the handler runs. On
denial the handler never executes, so nothing else would commit it and the
record of the attempt would roll back with the request. This means the decision
is durable regardless of whether the handler later succeeds.

Metadata carries only role names and the accepted set — never request bodies,
headers, or tokens.

### Write volume

Every authorized request writes a row. At MVP scale (5 concurrent challenges,
a small operator team) that is negligible, but it grows with traffic rather than
with interesting events. If it becomes a problem, the options in order of
preference are: record all denials but sample allows; or record allows only for
`SENSITIVE_ACTIONS`. Do not silently drop denials.

## A note on ordering audit rows

`created_at` defaults to PostgreSQL `now()`, which returns **transaction start
time**. Rows written in one transaction share a timestamp, so ordering by
`created_at` within a transaction is arbitrary. Filter by action or identifier
rather than assuming the newest row sorts first — this bit the tests once
already, and it will matter for the run-event stream (WO-009, WO-011).

## What this is not

This enforces *membership and role*. It does not evaluate project policy rules —
whether a specific challenge may be launched, an agent rerun, or a PR created
under current gates. That is WO-010, which should consume `ProjectContext`
rather than repeat these lookups.
