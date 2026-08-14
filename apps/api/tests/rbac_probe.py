"""Protected routes used to exercise the RBAC dependency over HTTP.

Defined in the test package rather than shipped in the application. The
dependency needs a real route to prove it runs before handler logic and returns
the right status codes, but a permanently mounted probe endpoint is an attack
surface with no product purpose. The test fixture mounts this router onto a real
app instance instead.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forgelab_api.api.dependencies import require_project_roles
from forgelab_api.domains.constants import ProjectAction, ProjectRole
from forgelab_api.domains.policy.rbac import ADMIN_ROLES, ALL_ROLES, ProjectContext

router = APIRouter(prefix="/projects/{project_id}", tags=["rbac-probe"])


class ProbeResponse(BaseModel):
    project_id: uuid.UUID
    role: ProjectRole
    action: ProjectAction
    handler_ran: bool


def _response(context: ProjectContext) -> ProbeResponse:
    return ProbeResponse(
        project_id=context.project_id,
        role=context.role,
        action=context.action,
        handler_ran=True,
    )


AdminOnly = Annotated[
    ProjectContext,
    Depends(require_project_roles(*ADMIN_ROLES, action=ProjectAction.CONNECT_REPOSITORY)),
]
AnyMember = Annotated[
    ProjectContext,
    Depends(require_project_roles(*ALL_ROLES, action=ProjectAction.REVIEW_RESULT)),
]
ReviewerOnly = Annotated[
    ProjectContext,
    Depends(require_project_roles(ProjectRole.REVIEWER, action=ProjectAction.APPROVE_RESULT)),
]
OperatorOnly = Annotated[
    ProjectContext,
    Depends(require_project_roles(ProjectRole.OPERATOR, action=ProjectAction.RERUN_FAILED_AGENT)),
]


@router.post("/admin-action", response_model=ProbeResponse)
async def admin_action(context: AdminOnly) -> ProbeResponse:
    return _response(context)


@router.get("/any-member-action", response_model=ProbeResponse)
async def any_member_action(context: AnyMember) -> ProbeResponse:
    return _response(context)


@router.post("/reviewer-action", response_model=ProbeResponse)
async def reviewer_action(context: ReviewerOnly) -> ProbeResponse:
    return _response(context)


@router.post("/operator-action", response_model=ProbeResponse)
async def operator_action(context: OperatorOnly) -> ProbeResponse:
    return _response(context)
