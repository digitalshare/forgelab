"""Session authentication routes.

The refresh token travels only as an HttpOnly cookie scoped to `/auth`, so it
is never readable by page scripts and is not attached to ordinary API calls.
The access token is returned in the response body for the client to hold in
memory and send as a bearer header.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.api.dependencies import CurrentActor
from forgelab_api.core.config import Settings, get_settings
from forgelab_api.core.request_context import get_request_id
from forgelab_api.db.session import get_session
from forgelab_api.domains.constants import ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS
from forgelab_api.domains.identity import service as identity_service

router = APIRouter(prefix="/auth", tags=["auth"])

SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


class BootstrapLoginRequest(BaseModel):
    tenant_slug: str = Field(min_length=1, max_length=100)
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    tenant_id: uuid.UUID
    user_id: uuid.UUID


class ActorResponse(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    session_id: uuid.UUID


class LogoutResponse(BaseModel):
    revoked: bool


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.refresh_cookie_samesite,  # type: ignore[arg-type]
        path=settings.refresh_cookie_path,
    )


def _clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.refresh_cookie_samesite,  # type: ignore[arg-type]
        path=settings.refresh_cookie_path,
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    agent = request.headers.get("user-agent")
    return agent[:512] if agent else None


def _unauthenticated(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: BootstrapLoginRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> TokenResponse:
    """Issue a session for a known active user.

    Bootstrap only — no secret is verified, because the user model has no
    credential to verify against. Disabled in production.
    """
    try:
        issued = await identity_service.bootstrap_login(
            session,
            tenant_slug=payload.tenant_slug,
            email=payload.email,
            enabled=settings.bootstrap_login_enabled,
            user_agent=_user_agent(request),
            ip_address=_client_ip(request),
            request_id=get_request_id(request),
        )
    except identity_service.BootstrapDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="bootstrap login is disabled in this environment",
        ) from exc
    except identity_service.AuthenticationError as exc:
        # Commit before raising: the failed-login audit record was written into
        # this transaction, and rejecting the request must not discard the
        # evidence that someone tried.
        await session.commit()
        raise _unauthenticated(str(exc)) from exc

    await session.commit()
    _set_refresh_cookie(response, issued.refresh_token, settings)
    return TokenResponse(
        access_token=issued.access_token,
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
        tenant_id=issued.tenant_id,
        user_id=issued.user_id,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> TokenResponse:
    """Rotate the refresh session and return a fresh access token."""
    token = request.cookies.get(settings.refresh_cookie_name)
    if not token:
        raise _unauthenticated("refresh cookie is missing")

    try:
        issued = await identity_service.rotate_refresh_session(
            session,
            refresh_token=token,
            user_agent=_user_agent(request),
            ip_address=_client_ip(request),
            request_id=get_request_id(request),
        )
    except identity_service.AuthenticationError as exc:
        # Commit first: a detected replay revokes the user's sessions, and that
        # revocation must survive the rejected request.
        await session.commit()
        _clear_refresh_cookie(response, settings)
        raise _unauthenticated(str(exc)) from exc

    await session.commit()
    _set_refresh_cookie(response, issued.refresh_token, settings)
    return TokenResponse(
        access_token=issued.access_token,
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
        tenant_id=issued.tenant_id,
        user_id=issued.user_id,
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    session: SessionDep,
    settings: SettingsDep,
) -> LogoutResponse:
    """Revoke the current refresh session. Idempotent."""
    token = request.cookies.get(settings.refresh_cookie_name)
    revoked = False
    if token:
        revoked = await identity_service.logout(
            session, refresh_token=token, request_id=get_request_id(request)
        )
        await session.commit()

    _clear_refresh_cookie(response, settings)
    return LogoutResponse(revoked=revoked)


@router.get("/me", response_model=ActorResponse)
async def me(actor: CurrentActor) -> ActorResponse:
    """Resolve the caller. Doubles as the protected endpoint in tests."""
    return ActorResponse(
        user_id=actor.user_id,
        tenant_id=actor.tenant_id,
        session_id=actor.session_id,
    )
