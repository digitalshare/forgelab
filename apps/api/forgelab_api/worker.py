"""arq worker entrypoint.

Agent runs and evaluation are CPU- and latency-heavy, so they execute here
rather than in the API process. Run with: `arq forgelab_api.worker.WorkerSettings`

The architecture allows either Celery or arq but forbids mixing them; this MVP
uses arq because the rest of the stack is async-native.
"""

from arq.connections import RedisSettings

from forgelab_api.core.config import get_settings

_settings = get_settings()


async def startup(ctx: dict) -> None:
    """Acquire shared clients once per worker process."""


async def shutdown(ctx: dict) -> None:
    """Release shared clients."""


class WorkerSettings:
    """Job functions are registered here as their work orders land.

    Planned: agent run execution (WO-033), sandbox provisioning (WO-027),
    sandbox cleanup (WO-031), stale-run reconciliation (WO-034), and the
    evaluation pipeline (WO-040).
    """

    functions: list = []
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(_settings.redis_url)
    max_jobs = 15
    job_timeout = 20 * 60
