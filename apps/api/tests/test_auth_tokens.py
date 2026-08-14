"""Unit tests for token signing, verification, and expiry. No database."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from forgelab_api.core.config import DEV_JWT_SECRET, Settings, get_settings
from forgelab_api.domains.constants import ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL
from forgelab_api.domains.identity.tokens import (
    ACCESS_TOKEN_TYPE,
    ExpiredTokenError,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)

USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
TENANT_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
SESSION_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")


def _token(**overrides):
    kwargs = {"user_id": USER_ID, "tenant_id": TENANT_ID, "session_id": SESSION_ID}
    kwargs.update(overrides)
    return create_access_token(**kwargs)


# --------------------------------------------------------------------------
# TTLs
# --------------------------------------------------------------------------


def test_access_token_lives_fifteen_minutes():
    assert ACCESS_TOKEN_TTL == timedelta(minutes=15)


def test_refresh_token_lives_seven_days():
    assert REFRESH_TOKEN_TTL == timedelta(days=7)


def test_access_token_is_far_shorter_lived_than_refresh():
    """Stateless credentials cannot be withdrawn, so they must expire quickly."""
    assert ACCESS_TOKEN_TTL < REFRESH_TOKEN_TTL


# --------------------------------------------------------------------------
# Signing and verification
# --------------------------------------------------------------------------


def test_token_round_trips_its_claims():
    token, claims = _token()
    decoded = decode_access_token(token)
    assert decoded.user_id == USER_ID
    assert decoded.tenant_id == TENANT_ID
    assert decoded.session_id == SESSION_ID
    assert decoded.token_id == claims.token_id


def test_expiry_is_one_ttl_after_issue():
    _, claims = _token()
    assert claims.expires_at - claims.issued_at == ACCESS_TOKEN_TTL


def test_each_token_has_a_distinct_identifier():
    _, first = _token()
    _, second = _token()
    assert first.token_id != second.token_id


def test_expired_token_is_rejected():
    token, _ = _token(now=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(ExpiredTokenError):
        decode_access_token(token)


def test_token_valid_up_to_its_expiry():
    token, _ = _token(now=datetime.now(UTC) - ACCESS_TOKEN_TTL + timedelta(seconds=30))
    assert decode_access_token(token).user_id == USER_ID


def test_tampered_token_is_rejected():
    token, _ = _token()
    head, payload, signature = token.split(".")
    with pytest.raises(InvalidTokenError):
        decode_access_token(f"{head}.{payload}x.{signature}")


def test_token_signed_with_another_key_is_rejected():
    forged = jwt.encode(
        {
            "sub": str(USER_ID),
            "tid": str(TENANT_ID),
            "sid": str(SESSION_ID),
            "jti": str(uuid.uuid4()),
            "typ": ACCESS_TOKEN_TYPE,
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        "an-entirely-different-secret",
        algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(forged)


def test_unsigned_token_is_rejected():
    """An `alg: none` token must never be accepted."""
    unsigned = jwt.encode({"sub": str(USER_ID)}, key="", algorithm="none")
    with pytest.raises(InvalidTokenError):
        decode_access_token(unsigned)


@pytest.mark.parametrize("garbage", ["", "not-a-token", "a.b", "....", "Bearer x"])
def test_malformed_tokens_are_rejected(garbage: str):
    with pytest.raises(InvalidTokenError):
        decode_access_token(garbage)


def test_token_of_the_wrong_type_is_rejected():
    """A future non-access JWT must not be usable as an access token."""
    settings = get_settings()
    other = jwt.encode(
        {
            "sub": str(USER_ID),
            "tid": str(TENANT_ID),
            "sid": str(SESSION_ID),
            "jti": str(uuid.uuid4()),
            "typ": "refresh",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(other)


def test_token_missing_required_claims_is_rejected():
    settings = get_settings()
    incomplete = jwt.encode(
        {"sub": str(USER_ID), "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(incomplete)


def test_token_with_non_uuid_subject_is_rejected():
    settings = get_settings()
    bad = jwt.encode(
        {
            "sub": "not-a-uuid",
            "tid": str(TENANT_ID),
            "sid": str(SESSION_ID),
            "jti": str(uuid.uuid4()),
            "typ": ACCESS_TOKEN_TYPE,
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(bad)


# --------------------------------------------------------------------------
# Refresh tokens
# --------------------------------------------------------------------------


def test_refresh_tokens_are_unique_and_long():
    tokens = {generate_refresh_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) >= 43 for t in tokens)


def test_hashing_is_deterministic_and_fits_the_column():
    token = generate_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)
    assert len(hash_refresh_token(token)) == 64


def test_hash_does_not_contain_the_token():
    token = generate_refresh_token()
    assert token not in hash_refresh_token(token)


def test_different_tokens_hash_differently():
    assert hash_refresh_token(generate_refresh_token()) != hash_refresh_token(
        generate_refresh_token()
    )


# --------------------------------------------------------------------------
# Signing configuration
# --------------------------------------------------------------------------


def test_development_default_secret_is_rejected_in_production():
    settings = Settings(environment="production", jwt_secret=DEV_JWT_SECRET)
    problems = settings.signing_secret_problems()
    assert any("development default" in p for p in problems)


def test_short_secret_is_rejected_in_production():
    settings = Settings(environment="production", jwt_secret="tooshort")
    assert any("32 characters" in p for p in settings.signing_secret_problems())


def test_bootstrap_login_must_be_off_in_production():
    settings = Settings(environment="production", allow_bootstrap_login=True)
    assert any("BOOTSTRAP" in p for p in settings.signing_secret_problems())
    assert settings.bootstrap_login_enabled is False


def test_production_with_a_real_secret_has_no_problems():
    settings = Settings(
        environment="production",
        jwt_secret="x" * 48,
        allow_bootstrap_login=False,
    )
    assert settings.signing_secret_problems() == []


def test_local_environment_is_unconstrained():
    assert Settings(environment="local").signing_secret_problems() == []


def test_cookies_are_insecure_only_for_local_development():
    assert Settings(environment="local").cookie_secure is False
    assert Settings(environment="staging").cookie_secure is True
    assert Settings(environment="production").cookie_secure is True
    assert Settings(environment="local", refresh_cookie_secure=True).cookie_secure is True
