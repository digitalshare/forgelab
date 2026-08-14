"""Reusable request dependencies."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from forgelab_api.db.session import get_session
from forgelab_api.domains.constants import ProjectAction, ProjectRole
from forgelab_api.domains.identity.models import RefreshSession
from forgelab_api.domains.identity.tokens import (
    ExpiredTokenError,
    InvalidTokenError,
    decode_access_token,
)
from forgelab_api.domains.policy.rbac import (
    AuthorizationDenied,
    DenyReason,
    ProjectContext,
    authorize_project_action,
)

_UNAUTHENTICATED_HEADERS = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True)
class Actor:
    """Who is making this request, and under which tenant."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    session_id: uuid.UUID


def _unauthenticated(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers=_UNAUTHENTICATED_HEADERS,
    )


async def get_current_actor(
    authorization: Annotated[str | None, Header()] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = ...,  # type: ignore[assignment]
) -> Actor:
    """Resolve the actor from a bearer access token.

    The signature check alone is not sufficient. Access tokens are stateless, so
    a token issued before a logout stays cryptographically valid until it
    expires; the underlying session is therefore re-checked against the database
    on every request. That costs one indexed lookup per call and is what makes
    logout and replay-revocation take effect immediately rather than up to
    fifteen minutes later.
    """
    if not authorization:
        raise _unauthenticated("authorization header is missing")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise _unauthenticated("authorization header must be a bearer token")

    try:
        claims = decode_access_token(token)
    except ExpiredTokenError as exc:
        raise _unauthenticated("access token has expired") from exc
    except InvalidTokenError as exc:
        raise _unauthenticated("access token is not valid") from exc

    record = await session.get(RefreshSession, claims.session_id)
    if record is None:
        raise _unauthenticated("session no longer exists")
    if record.revoked_at is not None:
        raise _unauthenticated("session has been revoked")
    if record.expires_at <= datetime.now(UTC):
        raise _unauthenticated("session has expired")
    if record.tenant_id != claims.tenant_id or record.user_id != claims.user_id:
        # The token's claims disagree with the stored session. Treat as hostile.
        raise _unauthenticated("session does not match token claims")

    return Actor(
        user_id=claims.user_id,
        tenant_id=claims.tenant_id,
        session_id=claims.session_id,
    )


CurrentActor = Annotated[Actor, Depends(get_current_actor)]


def require_project_roles(
    *allowed_roles: ProjectRole,
    action: ProjectAction,
) -> Callable[..., Awaitable[ProjectContext]]:
    """Build a dependency enforcing project membership and role for `action`.

    Usage on any project-scoped route with a `project_id` path parameter::

        @router.post("/projects/{project_id}/challenges")
        async def launch(
            context: Annotated[
                ProjectContext,
                Depends(require_project_roles(*ADMIN_ROLES,
                                              action=ProjectAction.LAUNCH_CHALLENGE)),
            ],
        ) -> ...:

    The handler receives a resolved `ProjectContext` and never repeats the
    membership lookup. Roles are listed explicitly — there is no hierarchy, so
    `require_project_roles(ProjectRole.MAINTAINER)` does **not** admit an Owner.

    Status codes are chosen so a denial reveals as little as possible:

    * ``404`` — the project does not exist, belongs to another tenant, or the
      actor is not a member. All three are indistinguishable, so membership
      cannot be used to enumerate projects.
    * ``403`` — the actor is a member but holds the wrong role. Nothing is
      leaked here that they could not already see.
    """
    if not allowed_roles:
        raise ValueError("require_project_roles needs at least one role")

    async def dependency(
        project_id: uuid.UUID,
        actor: CurrentActor,
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> ProjectContext:
        try:
            context = await authorize_project_action(
                session,
                actor_user_id=actor.user_id,
                tenant_id=actor.tenant_id,
                project_id=project_id,
                action=action,
                allowed_roles=allowed_roles,
            )
        except AuthorizationDenied as exc:
            # Commit before raising: the handler never runs, so without this the
            # record of the attempt would roll back with the request.
            await session.commit()
            if exc.reason is DenyReason.ROLE_NOT_PERMITTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="insufficient role for this action",
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="project not found"
            ) from exc

        # The allow record is committed here too, so the decision is durable
        # regardless of whether the handler later succeeds or fails.
        await session.commit()
        return context

    return dependency
