"""Top-level API router.

Domain routers are mounted here as their work orders land — challenges (WO-015),
the SSE event stream (WO-005), evaluation results (WO-045), and the PR gate
(WO-050).
"""

from fastapi import APIRouter

from forgelab_api.api.routes import auth, health, policy

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(policy.router)
