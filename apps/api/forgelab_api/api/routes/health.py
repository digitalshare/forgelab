"""Liveness and readiness probes."""

from fastapi import APIRouter
from sqlalchemy import text

from forgelab_api.core.redis import get_redis
from forgelab_api.db.session import SessionLocal

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    """Process is up. No dependency checks — used by the load balancer."""
    return {"status": "ok"}


@router.get("/readyz")
async def readiness() -> dict[str, object]:
    """Dependency check for Postgres and Redis."""
    checks: dict[str, str] = {}

    # A readiness probe must always answer. Connection failures surface as
    # OSError from the transport layer, not only as SQLAlchemyError/RedisError,
    # so both dependency checks catch broadly and report instead of raising.
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:  # noqa: BLE001 — probe reports, never propagates
        checks["postgres"] = f"error: {type(exc).__name__}"

    try:
        await get_redis().ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001 — probe reports, never propagates
        checks["redis"] = f"error: {type(exc).__name__}"

    ready = all(v == "ok" for v in checks.values())
    return {"ready": ready, "checks": checks}
