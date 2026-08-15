# Audit events

Delivered by WO-006. One writer, one table, one policy.

## Writing an event

```python
from forgelab_api.domains.audit import writer as audit
from forgelab_api.domains.constants import AuditAction, AuditOutcome

await audit.record_event(
    session,
    tenant_id=actor.tenant_id,
    action=AuditAction.CHALLENGE_LAUNCHED,
    outcome=AuditOutcome.PERMIT,
    actor_user_id=actor.user_id,
    project_id=project.id,
    request_id=get_request_id(request),
    metadata={"agents": 3},
)
```

`record_event` is the **only** way to write an audit row. The thin helper WO-002
left on the identity repository was removed — a second write path is a way to
bypass redaction and validation.

## Fields

| Field | Meaning |
|---|---|
| `tenant_id` | Required. Where the event happened, not where it was aimed. |
| `action` | What was attempted, from `AuditAction`. |
| `outcome` | `permit`, `deny`, `failure`, or `system`. |
| `actor_user_id` | Who. Null for system events and for failures where the actor is unknown. |
| `project_id`, `challenge_id`, `run_id` | Optional subjects. |
| `request_id` | Correlates every event from one request. |
| `reason` | Short explanation. Required for `deny` and `failure`. Truncated at 500 chars. |
| `metadata` | JSONB, redacted before write. |
| `created_at` | Server-side. See the ordering caveat below. |

### Choosing an outcome

`deny` is a decision that was evaluated and refused. `failure` is an attempt
that could not be evaluated at all — a malformed token, an unknown session.
Collapsing them makes "was this refused, or did it break?" unanswerable from the
trail, which is usually the first question asked during an incident.

`system` is for events with no human actor: sandbox cleanup, reconciliation,
expiry sweeps.

### Validation

- `permit` requires an actor. Something succeeded, so we know who.
- `deny` and `failure` require a reason. A refusal nobody explained cannot be
  investigated.
- `failure` does **not** require an actor. A rejected login is precisely the case
  where the actor is unknown; demanding one would force callers to invent an
  identity or skip auditing the attempt.

## Redaction is not optional

Metadata is redacted on every write. Callers cannot opt out — the callers most
likely to leak a token are the ones not thinking about it.

Two mechanisms, in `domains/audit/redaction.py`:

- **Key names** — any key containing `token`, `password`, `secret`,
  `authorization`, `cookie`, `api_key`, `private_key`, `jwt`, `hash`, and
  similar is replaced. Substring matching, so `refresh_token` and
  `authorization_header` are caught without enumerating variations.
- **Value shapes** — a compact JWT, or a value prefixed `Bearer`/`Basic`/`token`,
  is replaced whatever key it sits under. `{"detail": "Bearer eyJ..."}` is how
  these actually leak.

Values are **replaced** with `[redacted]`, not removed. A missing key is
ambiguous during an investigation; the marker says a value existed and was
withheld deliberately. Recursion is depth-bounded — an unbounded walk over
caller-supplied data is a denial-of-service waiting to happen.

Do not put user-supplied identifiers in metadata just because they are handy.
The failed-login path deliberately does not record the attempted email address:
a failed login is not a reason to accumulate addresses supplied by
unauthenticated callers.

## Transactions

`record_event` **flushes but does not commit**. The record joins the caller's
transaction, so an audited action and its evidence land together or not at all.

The exception is a rejected request, where the caller's work is about to be
discarded and the evidence would go with it. Those paths commit deliberately:

- `require_project_roles` on an authorization denial.
- The login route on a failed login.
- The refresh route on a rejected or replayed token.

If you add an audit call on a path that raises, check whether anything will
commit it.

## ⚠️ Ordering

`created_at` defaults to PostgreSQL `now()`, which returns **transaction start
time**. Every row written in one transaction shares a timestamp, so ordering by
`created_at` within a transaction is arbitrary.

Use `request_id` to group events from one request, and filter by `action` rather
than assuming the newest row sorts first. The run-event stream (WO-009, WO-011)
needs a monotonic sequence column rather than a timestamp — do not reuse this
pattern there.

## Adding an AuditAction or AuditOutcome

Adding an enum member does **not** change the database. Both `audit_action` and
`audit_outcome` are CHECK constraints that must be migrated by hand — Alembic
does not detect drift in non-native enum constraints. Worked examples:
`a1c4e77b21d5` and `c93f2a5e08b7`.

`test_every_audit_action_value_is_accepted_by_the_database` and
`test_every_outcome_is_accepted_by_the_database` fail loudly if the migration is
forgotten.

## Not in scope

No live dashboard, log aggregation, alerting, compliance reporting, retention
policy, or SIEM export. Retention in particular is unbounded today; the
architecture estimates ~1.5 GB of event metadata over a 30-day beta.
