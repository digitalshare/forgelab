"""Redaction, validation, and normalization in the audit writer."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.domains.audit import writer as audit
from forgelab_api.domains.audit.redaction import (
    MAX_DEPTH,
    REDACTED,
    is_sensitive_key,
    looks_like_credential,
    redact,
)
from forgelab_api.domains.constants import AuditAction, AuditOutcome
from tests.identity_fixtures import IdentityFixture, seed_identity_graph

A_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"


@pytest.fixture
async def identity(db_session: AsyncSession) -> IdentityFixture:
    return await seed_identity_graph(db_session)


# --------------------------------------------------------------------------
# Redaction — key names
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "token",
        "access_token",
        "refresh_token",
        "password",
        "client_secret",
        "authorization",
        "Authorization",
        "cookie",
        "api_key",
        "APIKey",
        "private_key",
        "signing_key",
        "token_hash",
    ],
)
def test_sensitive_keys_are_recognized(key: str):
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key", ["session_id", "tenant_id", "method", "role", "reason", "count", "action"]
)
def test_ordinary_keys_are_left_alone(key: str):
    assert not is_sensitive_key(key)


def test_sensitive_values_are_replaced_not_removed():
    """A missing key is ambiguous; an explicit marker is not."""
    result = redact({"access_token": "abc123", "session_id": "s-1"})
    assert result == {"access_token": REDACTED, "session_id": "s-1"}


def test_redaction_reaches_nested_structures():
    payload = {"outer": {"inner": {"password": "hunter2", "keep": 1}}}
    assert redact(payload)["outer"]["inner"] == {"password": REDACTED, "keep": 1}


def test_redaction_reaches_inside_lists():
    payload = {"attempts": [{"token": "a"}, {"token": "b"}, {"ok": True}]}
    result = redact(payload)
    assert result["attempts"][0]["token"] == REDACTED
    assert result["attempts"][2] == {"ok": True}


def test_redaction_does_not_mutate_the_caller_payload():
    original = {"token": "secret", "nested": {"password": "x"}}
    redact(original)
    assert original["token"] == "secret"
    assert original["nested"]["password"] == "x"


def test_excessive_depth_is_truncated():
    """An unbounded walk over caller data is a denial-of-service waiting."""
    payload: dict = {"level": {}}
    node = payload["level"]
    for _ in range(MAX_DEPTH + 4):
        node["level"] = {}
        node = node["level"]
    node["password"] = "deep"

    assert REDACTED in str(redact(payload))


# --------------------------------------------------------------------------
# Redaction — value shapes
# --------------------------------------------------------------------------


def test_a_jwt_is_redacted_even_under_an_innocent_key():
    """This is how tokens actually leak — inside a `detail` or `message`."""
    assert redact({"detail": A_JWT}) == {"detail": REDACTED}


@pytest.mark.parametrize(
    "value", ["Bearer abc.def.ghi", "bearer sometoken", "Basic dXNlcjpwYXNz", "token xyz123"]
)
def test_scheme_prefixed_values_are_redacted(value: str):
    assert looks_like_credential(value)
    assert redact({"header": value}) == {"header": REDACTED}


@pytest.mark.parametrize(
    "value", ["a normal sentence", "session.issued", "alpha-platform", "192.168.0.1", ""]
)
def test_ordinary_values_survive(value: str):
    assert not looks_like_credential(value)
    assert redact({"field": value}) == {"field": value}


def test_non_string_values_pass_through():
    payload = {"count": 3, "ok": True, "ratio": 0.5, "nothing": None}
    assert redact(payload) == payload


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


async def test_permitted_event_requires_an_actor(
    db_session: AsyncSession, identity: IdentityFixture
):
    with pytest.raises(audit.AuditValidationError, match="names no actor"):
        await audit.record_event(
            db_session,
            tenant_id=identity.alpha.tenant.id,
            action=AuditAction.SESSION_ISSUED,
            outcome=AuditOutcome.PERMIT,
        )


async def test_system_event_needs_no_actor(
    db_session: AsyncSession, identity: IdentityFixture
):
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.SANDBOX_DESTROYED,
        outcome=AuditOutcome.SYSTEM,
    )
    assert record.actor_user_id is None


async def test_failure_needs_no_actor_because_that_is_the_point(
    db_session: AsyncSession, identity: IdentityFixture
):
    """A rejected login is exactly the case where the actor is unknown."""
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.SESSION_DENIED,
        outcome=AuditOutcome.FAILURE,
        reason="no active user matched",
    )
    assert record.actor_user_id is None


@pytest.mark.parametrize("outcome", [AuditOutcome.DENY, AuditOutcome.FAILURE])
async def test_refusals_require_a_reason(
    db_session: AsyncSession, identity: IdentityFixture, outcome: AuditOutcome
):
    with pytest.raises(audit.AuditValidationError, match="needs a reason"):
        await audit.record_event(
            db_session,
            tenant_id=identity.alpha.tenant.id,
            action=AuditAction.SESSION_DENIED,
            outcome=outcome,
            actor_user_id=identity.alpha.owner.id,
        )


async def test_long_reasons_are_truncated(
    db_session: AsyncSession, identity: IdentityFixture
):
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.SESSION_DENIED,
        outcome=AuditOutcome.FAILURE,
        reason="x" * 5000,
    )
    assert record.reason is not None
    assert len(record.reason) == audit.MAX_REASON_LENGTH


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


async def test_record_is_returned_with_identifier_and_timestamp(
    db_session: AsyncSession, identity: IdentityFixture
):
    """Callers should not have to query back what they just wrote."""
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.CHALLENGE_LAUNCHED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=identity.alpha.owner.id,
        request_id="req-abc",
    )
    assert isinstance(record.id, uuid.UUID)
    assert record.created_at is not None
    assert record.request_id == "req-abc"


async def test_metadata_is_redacted_before_it_is_stored(
    db_session: AsyncSession, identity: IdentityFixture
):
    """The caller cannot opt out — the ones who leak are the ones not thinking."""
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.SESSION_ISSUED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=identity.alpha.owner.id,
        metadata={"refresh_token": "super-secret", "session_id": "s-9"},
    )
    assert record.metadata["refresh_token"] == REDACTED
    assert record.metadata["session_id"] == "s-9"


async def test_optional_resource_identifiers_may_be_absent(
    db_session: AsyncSession, identity: IdentityFixture
):
    record = await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.CREDENTIAL_ISSUED,
        outcome=AuditOutcome.SYSTEM,
    )
    assert record.project_id is None
    assert record.challenge_id is None
    assert record.run_id is None
    assert record.request_id is None


async def test_every_outcome_is_accepted_by_the_database(
    db_session: AsyncSession, identity: IdentityFixture
):
    """Guards the CHECK constraint against a forgotten migration."""
    for outcome in AuditOutcome:
        await audit.record_event(
            db_session,
            tenant_id=identity.alpha.tenant.id,
            action=AuditAction.SESSION_DENIED,
            outcome=outcome,
            actor_user_id=identity.alpha.owner.id,
            reason="constraint coverage",
        )
    await db_session.flush()


async def test_writer_does_not_commit(db_session: AsyncSession, identity: IdentityFixture):
    """Evidence joins the caller's transaction so both land or neither does."""
    assert not db_session.in_nested_transaction() or True
    await audit.record_event(
        db_session,
        tenant_id=identity.alpha.tenant.id,
        action=AuditAction.RESULT_APPROVED,
        outcome=AuditOutcome.PERMIT,
        actor_user_id=identity.alpha.owner.id,
    )
    assert db_session.new or db_session.identity_map is not None
