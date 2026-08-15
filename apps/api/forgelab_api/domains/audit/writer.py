"""Durable audit writer.

Every sensitive decision — identity, authorization, credentials, project actions
— records what happened here. The writer owns three things callers should not
each reimplement: redaction of credential material, normalization of outcomes,
and validation that a record carries the fields an investigator will need.

**Writes are not committed here.** The record joins the caller's transaction, so
an audited action and its evidence land together or not at all. The one place
that must not follow this rule is a *denial*, where the caller's work is about
to be discarded — see `require_project_roles`, which commits deliberately so the
record of a rejected attempt survives the rejection.

Persistence is PostgreSQL only. No Redis, no external log shipper, nothing that
can be unavailable at the moment something goes wrong. The writer returns the
persisted record so callers can assert on it without querying anything back.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.audit.redaction import redact
from forgelab_api.domains.constants import AuditAction, AuditOutcome
from forgelab_api.domains.identity.models import AuditEvent

#: Reasons longer than this are truncated. A reason is a short explanation, not
#: a place to put a stack trace or a response body.
MAX_REASON_LENGTH = 500


class AuditValidationError(ValueError):
    """The record is missing something an investigator would need."""


@dataclass(frozen=True)
class AuditRecord:
    """The persisted event, returned so callers need not query it back."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    action: AuditAction
    outcome: AuditOutcome
    actor_user_id: uuid.UUID | None
    project_id: uuid.UUID | None
    challenge_id: uuid.UUID | None
    run_id: uuid.UUID | None
    request_id: str | None
    reason: str | None
    metadata: dict[str, Any]
    created_at: datetime | None


async def record_event(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: AuditAction,
    outcome: AuditOutcome,
    actor_user_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    challenge_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    request_id: str | None = None,
    reason: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> AuditRecord:
    """Persist one audit event and return it.

    Metadata is redacted before it is written — a caller cannot opt out, because
    the callers most likely to leak a token are the ones not thinking about it.

    Raises:
        AuditValidationError: a permitted action carries no actor, or a denial
            or failure carries no reason. Both make a record unusable for the
            question it exists to answer.
    """
    # Only PERMIT requires an actor. A rejected login is precisely the case
    # where the actor is unknown — that is what makes it a failure — so
    # demanding one would force callers either to invent an identity or to skip
    # auditing the attempt entirely.
    if outcome is AuditOutcome.PERMIT and actor_user_id is None:
        raise AuditValidationError(
            f"{action.value} was permitted but names no actor; "
            "use AuditOutcome.SYSTEM for events with no human actor"
        )

    if outcome in {AuditOutcome.DENY, AuditOutcome.FAILURE} and not reason:
        raise AuditValidationError(
            f"{action.value} with outcome {outcome.value} needs a reason; "
            "a refusal nobody explained cannot be investigated"
        )

    safe_metadata = redact(dict(metadata)) if metadata else {}
    trimmed_reason = reason[:MAX_REASON_LENGTH] if reason else None

    event = AuditEvent(
        tenant_id=tenant_id,
        action=action,
        outcome=outcome,
        actor_user_id=actor_user_id,
        project_id=project_id,
        challenge_id=challenge_id,
        run_id=run_id,
        request_id=request_id,
        reason=trimmed_reason,
        event_metadata=safe_metadata,
    )
    session.add(event)
    # Flush so the identifier and server-side timestamp exist for the caller,
    # without committing — the record belongs to the caller's transaction.
    await session.flush()

    return AuditRecord(
        id=event.id,
        tenant_id=event.tenant_id,
        action=event.action,
        outcome=outcome,
        actor_user_id=event.actor_user_id,
        project_id=event.project_id,
        challenge_id=event.challenge_id,
        run_id=event.run_id,
        request_id=event.request_id,
        reason=event.reason,
        metadata=safe_metadata,
        created_at=event.created_at,
    )
